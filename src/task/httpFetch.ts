import * as http from 'http';
import * as https from 'https';
import { URL } from 'url';
import { FetchLike } from './ConfigClient';

// 30s is generous for a small settings document on a local network, and short enough that a
// build does not sit for its full job timeout waiting on a settings endpoint that stopped
// responding.
const DEFAULT_TIMEOUT_MS = 30_000;

/**
 * Minimal fetch-like GET client built on `http`/`https`, so the task runs on Node 16, which has
 * no global `fetch`.
 *
 * The response body is decoded as UTF-8 unconditionally. That is safe because the only caller,
 * the Extension Data Service, always returns UTF-8 JSON. A server replying with a different
 * charset would not necessarily fail visibly: if the JSON structure itself stays ASCII, a
 * non-UTF-8 byte inside a string value is silently replaced with U+FFFD while `JSON.parse` still
 * succeeds. `Content-Encoding: gzip` is not decoded either, but that failure mode is loud rather
 * than silent: the compressed bytes decode to garbage text that fails `JSON.parse` in
 * `ConfigClient`. Neither charset negotiation nor gzip decoding is implemented on purpose — the
 * single endpoint this talks to needs neither, and either would be surface with no caller.
 *
 * Accepts an optional timeout in milliseconds, beyond the `FetchLike` contract: a function with an
 * extra optional parameter is still structurally assignable wherever a `FetchLike` is expected
 * (e.g. `new ConfigClient({ ..., fetch: httpFetch })`), so `ConfigClient` keeps using the 30s
 * default while tests can pass a short one to stay fast.
 */
export function httpFetch(
  url: string,
  init: { headers: Record<string, string> },
  timeoutMs: number = DEFAULT_TIMEOUT_MS,
): Promise<{ ok: boolean; status: number; text(): Promise<string> }> {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const transport = parsed.protocol === 'http:' ? http : https;
    // Guards against a timeout firing after the response already completed (or after we already
    // rejected for some other reason): the promise must settle exactly once, and a late timer
    // must not destroy a socket we are already done with.
    let settled = false;

    const request = transport.request(
      parsed,
      { method: 'GET', headers: init.headers },
      (response) => {
        let body = '';
        response.setEncoding('utf8');
        response.on('data', (chunk: string) => {
          body += chunk;
        });
        response.on('end', () => {
          if (settled) {
            return;
          }
          settled = true;
          request.setTimeout(0); // cancel the watchdog: the response is complete.
          const status = response.statusCode ?? 0;
          resolve({ ok: status >= 200 && status < 300, status, text: async () => body });
        });
      },
    );

    // Fires when the socket has been idle for `timeoutMs`, whether that idle period is before
    // any response arrives at all, or after headers (and possibly a partial body) arrive and the
    // rest of the body never does. Either way this is the only thing standing between a stalled
    // settings endpoint and a promise that never resolves or rejects.
    request.setTimeout(timeoutMs, () => {
      if (settled) {
        return;
      }
      settled = true;
      // Named so ConfigClient can turn this into an actionable message; deliberately carries no
      // header values.
      const timeoutError = new Error(`Request to ${url} timed out after ${timeoutMs}ms.`);
      reject(timeoutError);
      request.destroy(timeoutError);
    });

    request.on('error', (error) => {
      if (settled) {
        return;
      }
      settled = true;
      reject(error);
    });
    request.end();
  });
}

// Compile-time proof that httpFetch satisfies the contract ConfigClient actually depends on.
const _satisfiesFetchLike: FetchLike = httpFetch;
void _satisfiesFetchLike;
