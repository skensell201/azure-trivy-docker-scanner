import * as http from 'http';
import * as net from 'net';
import * as zlib from 'zlib';
import { AddressInfo } from 'net';
import { httpFetch } from '../httpFetch';

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
  });
});
