import * as http from 'http';
import * as https from 'https';
import { URL } from 'url';
import { FetchLike } from './ConfigClient';

// 30s is generous for a small settings document on a local network, and short enough that a
// build does not sit for its full job timeout waiting on a settings endpoint that stopped
// responding. Exported so tests can assert on the actual value instead of waiting 30 seconds for
// the default to expire — and so a future change to it does not silently regress unnoticed.
export const DEFAULT_TIMEOUT_MS = 30_000;

// A settings document (the runner catalog, project defaults) is a few kilobytes; 1 MiB is
// generous headroom. The body is capped rather than left unbounded: without this, a misbehaving
// or malicious endpoint could hold the process buffering an arbitrarily large response in memory.
export const MAX_BODY_BYTES = 1024 * 1024;

/**
 * Strips userinfo (`user:pass@`) before a URL is interpolated into an error message. Nothing
 * downstream needs credentials in a message, and `System.CollectionUri`-derived URLs are the one
 * input whose shape this module does not fully control.
 */
function sanitizeUrlForDisplay(rawUrl: string): string {
  try {
    const copy = new URL(rawUrl);
    copy.username = '';
    copy.password = '';
    return copy.toString();
  } catch {
    return rawUrl;
  }
}

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
 * (e.g. `new ConfigClient({ ..., fetch: httpFetch })`), so `ConfigClient` keeps using the default
 * while tests can pass a short one to stay fast.
 */
export function httpFetch(
  url: string,
  init: { headers: Record<string, string> },
  timeoutMs: number = DEFAULT_TIMEOUT_MS,
): Promise<{ ok: boolean; status: number; text(): Promise<string> }> {
  const displayUrl = sanitizeUrlForDisplay(url);

  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const transport = parsed.protocol === 'http:' ? http : https;
    // The promise must settle exactly once. This guards every settle path below: the overall
    // deadline, a premature close routed onto the response rather than the request, the body cap,
    // a transport error, and normal completion can all race each other, and only the first one
    // may act.
    let settled = false;

    const finish = (action: () => void): void => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(deadline);
      action();
    };

    const request = transport.request(
      parsed,
      { method: 'GET', headers: init.headers },
      (response) => {
        let body = '';
        let bytesReceived = 0;
        response.setEncoding('utf8');

        response.on('data', (chunk: string) => {
          if (settled) {
            return;
          }
          bytesReceived += Buffer.byteLength(chunk, 'utf8');
          if (bytesReceived > MAX_BODY_BYTES) {
            finish(() => {
              reject(
                new Error(`Response from ${displayUrl} exceeded the ${MAX_BODY_BYTES} byte limit.`),
              );
              request.destroy();
            });
            return;
          }
          body += chunk;
        });

        response.on('end', () => {
          finish(() => {
            const status = response.statusCode ?? 0;
            resolve({ ok: status >= 200 && status < 300, status, text: async () => body });
          });
        });

        // Node routes a premature close of the underlying connection — a reset, or a graceful
        // FIN that arrives before Content-Length is satisfied — onto the *response*, not the
        // request: `request.on('error', ...)` alone never observes it and the promise would hang
        // past its deadline. Verified empirically for both a destroyed socket (RST) and
        // socket.end() with an unmet Content-Length before these two listeners existed.
        response.on('aborted', () => {
          finish(() => {
            reject(new Error(`Request to ${displayUrl} closed before the response completed.`));
          });
        });
        response.on('error', (error) => {
          finish(() => {
            reject(
              new Error(
                `Request to ${displayUrl} failed while reading the response: ${(error as Error).message}`,
              ),
            );
          });
        });
      },
    );

    // A single deadline over the whole request/response lifecycle — connecting, headers, and
    // body — rather than an idle watchdog. `request.setTimeout` resets on every byte received, so
    // a server dripping one byte just under that window defeats it indefinitely; verified
    // empirically (a 200ms idle timeout let a request resolve at over 6x its budget under a
    // steady drip). This timer fires exactly once regardless of how much partial progress the
    // server makes, and `finish` clears it as soon as anything else settles the promise first, so
    // a late fire can neither destroy a socket already finished with nor reject an already-settled
    // promise.
    const deadline = setTimeout(() => {
      finish(() => {
        reject(new Error(`Request to ${displayUrl} timed out after ${timeoutMs}ms.`));
        request.destroy();
      });
    }, timeoutMs);

    request.on('error', (error) => {
      finish(() => reject(error));
    });
    request.end();
  });
}

// Compile-time proof that httpFetch satisfies the contract ConfigClient actually depends on.
const _satisfiesFetchLike: FetchLike = httpFetch;
void _satisfiesFetchLike;
