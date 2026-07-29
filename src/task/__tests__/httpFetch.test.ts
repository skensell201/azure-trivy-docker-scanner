import * as http from 'http';
import * as net from 'net';
import * as zlib from 'zlib';
import { AddressInfo } from 'net';
import { httpFetch, DEFAULT_TIMEOUT_MS, MAX_BODY_BYTES } from '../httpFetch';

describe('httpFetch', () => {
  let server: http.Server;
  let base: string;
  let seenAuth: string | undefined;

  beforeAll((done) => {
    server = http.createServer((request, response) => {
      seenAuth = request.headers.authorization;
      if (request.url?.includes('missing')) {
        response.writeHead(404).end('nope');
        return;
      }
      if (request.url?.includes('redirect')) {
        response.writeHead(302, { location: '/doc' }).end();
        return;
      }
      if (request.url?.includes('gzip')) {
        // A well-behaved settings endpoint never does this (no Accept-Encoding is sent, so no
        // compliant server should compress), but a misbehaving proxy might. Pins that the client
        // does not attempt to decompress: the caller sees the raw bytes, not silently wrong JSON.
        response
          .writeHead(200, { 'content-type': 'application/json', 'content-encoding': 'gzip' })
          .end(zlib.gzipSync(Buffer.from('{"value":[1,2]}', 'utf8')));
        return;
      }
      response.writeHead(200, { 'content-type': 'application/json' }).end('{"value":[1,2]}');
    });
    server.listen(0, '127.0.0.1', () => {
      base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
      done();
    });
  });

  afterAll((done) => {
    server.close(() => done());
  });

  it('returns ok with the body for a 200 response', async () => {
    const response = await httpFetch(`${base}/doc`, { headers: {} });
    expect(response.ok).toBe(true);
    expect(response.status).toBe(200);
    await expect(response.text()).resolves.toBe('{"value":[1,2]}');
  });

  it('sends the authorization header', async () => {
    await httpFetch(`${base}/doc`, { headers: { Authorization: 'Bearer tok' } });
    expect(seenAuth).toBe('Bearer tok');
  });

  it('reports a non-ok status without throwing', async () => {
    const response = await httpFetch(`${base}/missing`, { headers: {} });
    expect(response).toMatchObject({ ok: false, status: 404 });
  });

  it('rejects when the host refuses the connection', async () => {
    await expect(httpFetch('http://127.0.0.1:1/doc', { headers: {} })).rejects.toThrow();
  });

  // A redirect is not followed automatically: the Authorization header must never be replayed
  // against a Location the caller has not vetted. ConfigClient turns this ok:false into an
  // actionable error rather than the request silently landing somewhere else with the token.
  it('does not follow a redirect: a 3xx response comes back as ok:false with its own status', async () => {
    const response = await httpFetch(`${base}/redirect`, { headers: {} });
    expect(response).toMatchObject({ ok: false, status: 302 });
  });

  // Pins that Content-Encoding is not inspected or decompressed: a gzip body surfaces as its raw
  // (compressed) bytes decoded as UTF-8 text, not as decompressed JSON. This is a deliberate
  // scope limit, not an oversight, so a caller pointing this at a compressing endpoint gets
  // visibly broken JSON.parse output instead of a silently "working" client that only sometimes is.
  it('does not decode a gzip-encoded response body', async () => {
    const response = await httpFetch(`${base}/gzip`, { headers: {} });
    expect(response.ok).toBe(true);
    const text = await response.text();
    expect(text).not.toBe('{"value":[1,2]}');
    expect(() => JSON.parse(text)).toThrow();
  });

  it('does not leak the Authorization header value into a transport failure', async () => {
    const secret = 'Bearer super-secret-token-xyz';
    await expect(
      httpFetch('http://127.0.0.1:1/doc', { headers: { Authorization: secret } }),
    ).rejects.not.toMatchObject({ message: expect.stringContaining(secret) });
  });

  describe('timeout', () => {
    // Without a watchdog, a settings endpoint that hangs leaves the promise pending forever and
    // the build sits until the agent's own job timeout kills it with no useful explanation. Both
    // servers below use a raw `net.createServer` rather than `http.createServer`: an http server
    // always answers something once it decides to handle a request, so a raw socket that simply
    // never writes is the only reliable way to simulate "accepted, then silence".

    it('rejects when the server accepts the connection but never responds', async () => {
      const stuckServer = net.createServer(() => {
        // Accept the TCP connection and do nothing: no bytes, ever.
      });
      await new Promise<void>((resolve) => stuckServer.listen(0, '127.0.0.1', () => resolve()));
      const port = (stuckServer.address() as AddressInfo).port;

      try {
        await expect(
          httpFetch(`http://127.0.0.1:${port}/doc`, { headers: {} }, 50),
        ).rejects.toThrow(/timed out/i);
      } finally {
        stuckServer.close();
      }
    });

    it('rejects when headers and part of the body arrive but the rest never does', async () => {
      const stuckServer = net.createServer((socket) => {
        socket.write(
          'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n',
        );
        socket.write('{"partial":true');
        // Then nothing further, ever: Content-Length promised 100 bytes, only ~16 arrive.
      });
      await new Promise<void>((resolve) => stuckServer.listen(0, '127.0.0.1', () => resolve()));
      const port = (stuckServer.address() as AddressInfo).port;

      try {
        await expect(
          httpFetch(`http://127.0.0.1:${port}/doc`, { headers: {} }, 50),
        ).rejects.toThrow(/timed out/i);
      } finally {
        stuckServer.close();
      }
    });

    it('names the URL in the timeout message without leaking headers', async () => {
      const stuckServer = net.createServer(() => {
        // Accept and never respond.
      });
      await new Promise<void>((resolve) => stuckServer.listen(0, '127.0.0.1', () => resolve()));
      const port = (stuckServer.address() as AddressInfo).port;
      const url = `http://127.0.0.1:${port}/doc`;
      const secret = 'Bearer super-secret-token-xyz';

      try {
        await expect(
          httpFetch(url, { headers: { Authorization: secret } }, 50),
        ).rejects.toThrow(new RegExp(`${port}.*timed out`));
        await expect(
          httpFetch(url, { headers: { Authorization: secret } }, 50),
        ).rejects.not.toMatchObject({ message: expect.stringContaining(secret) });
      } finally {
        stuckServer.close();
      }
    });

    // If a collectionUri ever carried userinfo (https://user:secret@host/...), it must not land in
    // a build log via an error message. The connection-refused test above already shows Node's own
    // transport errors never include the URL at all; this pins the messages this module
    // constructs itself (timeout, premature close, body cap all share the same sanitized URL).
    it('strips userinfo from the URL before it appears in a timeout message', async () => {
      const stuckServer = net.createServer(() => {
        // Accept and never respond.
      });
      await new Promise<void>((resolve) => stuckServer.listen(0, '127.0.0.1', () => resolve()));
      const port = (stuckServer.address() as AddressInfo).port;
      const url = `http://user:s3cr3t-pass@127.0.0.1:${port}/doc`;

      try {
        const failure = httpFetch(url, { headers: {} }, 50);
        await expect(failure).rejects.toThrow(/timed out/);
        await failure.catch((error: Error) => {
          expect(error.message).not.toContain('s3cr3t-pass');
          expect(error.message).not.toContain('user:');
        });
      } finally {
        stuckServer.close();
      }
    });

    // A reviewer found that the idle watchdog above is not enough: Node routes a premature close
    // of the connection onto the *response*, not the request, so `request.on('error')` alone
    // never sees it. Verified empirically before this test existed: both a destroyed socket (RST)
    // and a graceful socket.end() with an unmet Content-Length left the promise pending for 4s+
    // past a configured 1000ms timeout.

    it('rejects rather than hanging when the connection resets mid-body (RST)', async () => {
      const stuckServer = net.createServer((socket) => {
        socket.write(
          'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n',
        );
        socket.write('{"partial":true');
        socket.destroy();
      });
      await new Promise<void>((resolve) => stuckServer.listen(0, '127.0.0.1', () => resolve()));
      const port = (stuckServer.address() as AddressInfo).port;

      try {
        await expect(httpFetch(`http://127.0.0.1:${port}/doc`, { headers: {} }, 2000)).rejects.toThrow();
      } finally {
        stuckServer.close();
      }
    }, 4000);

    it('rejects rather than hanging when the connection closes gracefully mid-body (unmet Content-Length)', async () => {
      const stuckServer = net.createServer((socket) => {
        socket.write(
          'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n',
        );
        socket.write('{"partial":true');
        socket.end();
      });
      await new Promise<void>((resolve) => stuckServer.listen(0, '127.0.0.1', () => resolve()));
      const port = (stuckServer.address() as AddressInfo).port;

      try {
        await expect(httpFetch(`http://127.0.0.1:${port}/doc`, { headers: {} }, 2000)).rejects.toThrow();
      } finally {
        stuckServer.close();
      }
    }, 4000);

    // A reviewer found that `request.setTimeout` is an idle watchdog: it resets on every byte, so
    // a server that drips one byte just under the window defeats it indefinitely. Verified
    // empirically: with a 200ms timeout and a byte every 60ms, the request resolved at 1225ms —
    // over 6x its configured budget. The fix is a single deadline covering the whole exchange.
    it('rejects once the overall deadline elapses even under a steady drip of bytes', async () => {
      const TOTAL_BYTES = 20;
      const DRIP_INTERVAL_MS = 60;
      const TIMEOUT_MS = 200;
      const dripServer = net.createServer((socket) => {
        // Once the client hits its deadline it destroys its end of the connection; the drip
        // keeps trying to write afterwards and would otherwise crash the process with an
        // unhandled EPIPE. That is expected here and is not something the test needs to verify.
        socket.on('error', () => undefined);
        socket.write(
          `HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ${TOTAL_BYTES}\r\n\r\n`,
        );
        let sent = 0;
        const drip = setInterval(() => {
          if (sent >= TOTAL_BYTES || socket.destroyed) {
            clearInterval(drip);
            return;
          }
          socket.write('a');
          sent += 1;
        }, DRIP_INTERVAL_MS);
        socket.on('close', () => clearInterval(drip));
      });
      await new Promise<void>((resolve) => dripServer.listen(0, '127.0.0.1', () => resolve()));
      const port = (dripServer.address() as AddressInfo).port;

      try {
        const start = Date.now();
        await expect(
          httpFetch(`http://127.0.0.1:${port}/doc`, { headers: {} }, TIMEOUT_MS),
        ).rejects.toThrow(/timed out/i);
        // The drip alone runs for TOTAL_BYTES * DRIP_INTERVAL_MS = 1200ms; an idle-reset watchdog
        // would let it run that long. The deadline must cut it off close to TIMEOUT_MS instead.
        expect(Date.now() - start).toBeLessThan(TOTAL_BYTES * DRIP_INTERVAL_MS);
      } finally {
        dripServer.close();
      }
    }, 4000);

    // Every other test above passes an explicit, short timeoutMs, so none of them would notice if
    // the default itself regressed (mutation testing showed changing 30s to roughly 24 days still
    // passes the suite). Assert on the exported constant directly instead of waiting 30 seconds.
    it('defaults to 30 seconds when no timeout is given', () => {
      expect(DEFAULT_TIMEOUT_MS).toBe(30_000);
    });

    // Pins that the deadline timer is actually cancelled once the response resolves — not just
    // that a late fire is harmless by luck. Mutation testing showed that dropping the
    // `clearTimeout` call on success still passes every behavioral test above, because a
    // superfluous `request.destroy()` after the body is already captured has no visible effect on
    // the resolved value. Spying on the global is the only way to observe the cleanup itself.
    it('cancels the deadline timer once the response resolves', async () => {
      const clearTimeoutSpy = jest.spyOn(global, 'clearTimeout');
      const callsBefore = clearTimeoutSpy.mock.calls.length;

      await httpFetch(`${base}/doc`, { headers: {} }, 10_000);

      expect(clearTimeoutSpy.mock.calls.length).toBeGreaterThan(callsBefore);
      clearTimeoutSpy.mockRestore();
    });
  });

  describe('body cap', () => {
    it('rejects a response larger than the byte limit, naming the limit', async () => {
      const oversizedBody = 'a'.repeat(MAX_BODY_BYTES + 1024);
      const oversizedServer = http.createServer((_request, response) => {
        response.writeHead(200, { 'content-type': 'text/plain' }).end(oversizedBody);
      });
      await new Promise<void>((resolve) => oversizedServer.listen(0, '127.0.0.1', () => resolve()));
      const port = (oversizedServer.address() as AddressInfo).port;

      try {
        await expect(
          httpFetch(`http://127.0.0.1:${port}/doc`, { headers: {} }, 5000),
        ).rejects.toThrow(new RegExp(`exceeded.*${MAX_BODY_BYTES}`, 's'));
      } finally {
        oversizedServer.close();
      }
    });

    // A second settle attempt must not change an outcome that already landed. The cap rejection
    // (and the request.destroy() that comes with it) happens first and is given time to complete;
    // only then does the server independently tear its own side down too, which reaches the
    // client as a request/response-level error on an already-destroyed request. Without the
    // `settled` guard this would try to reject a second time with a different message
    // (e.g. ECONNRESET); a Promise only ever keeps its first settled value, so this test checks
    // that the outcome the caller actually sees is still the cap message, not that second error.
    it('keeps the body-cap outcome when the connection also tears down shortly after', async () => {
      const oversizedBody = Buffer.alloc(MAX_BODY_BYTES + 4096, 'a');
      const raceServer = net.createServer((socket) => {
        socket.on('error', () => undefined);
        socket.write(
          `HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: ${oversizedBody.length}\r\n\r\n`,
        );
        socket.write(oversizedBody);
        // Long enough for the client to have already processed the oversized write and settled
        // on its own cap rejection (sub-millisecond over loopback), well before this fires.
        setTimeout(() => socket.destroy(), 100);
      });
      await new Promise<void>((resolve) => raceServer.listen(0, '127.0.0.1', () => resolve()));
      const port = (raceServer.address() as AddressInfo).port;

      try {
        await expect(
          httpFetch(`http://127.0.0.1:${port}/doc`, { headers: {} }, 5000),
        ).rejects.toThrow(/exceeded/i);
      } finally {
        raceServer.close();
      }
    });
  });
});
