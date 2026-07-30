import * as http from 'http';
import * as https from 'https';
import { URL } from 'url';
import { FetchLike } from './ConfigClient';

// 30s is generous for a small settings document on a local network, and short enough that a
// build does not sit for its full job timeout waiting on a settings endpoint that stopped
// responding. Exported so tests can assert on the actual value instead of waiting 30 seconds for
// the default to expire — and so a future change to it does not silently regress unnoticed.
export const DEFAULT_TIMEOUT_MS = 30_000;

// A settings document (the runner catalog, collection defaults) is a few kilobytes; 1 MiB is
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
 * Options for {@link createHttpFetch}. Deliberately does not include `certFile`/`keyFile`: a
 * client certificate is a different feature (mutual TLS) from trusting an internal CA, nobody has
 * asked for it, and half-implementing it here would be worse than not having it — see the comment
 * at the `certFile`/`keyFile` call site in `index.ts` for the reasoning.
 */
export interface CreateHttpFetchOptions {
  /**
   * Extra certificate authority to trust, in addition to Node's bundled root store — typically
   * the contents of the agent's `--sslcacert` file (`tl.getHttpCertConfiguration().caFile`), read
   * by the caller. Passed straight through to `https.request`'s own `ca` option, so it accepts
   * whatever that accepts (a single PEM string/Buffer, PEM chain, etc.).
   */
  ca?: string | Buffer;
  /**
   * Default timeout in milliseconds applied to requests made with the returned function when the
   * call site does not pass its own (see the third parameter of the returned `FetchLike`).
   * Defaults to {@link DEFAULT_TIMEOUT_MS}.
   */
  timeoutMs?: number;
}

/**
 * Core of the fetch-like GET client shared by `httpFetch` and every closure `createHttpFetch`
 * returns, built on `http`/`https` so the task runs on Node 16, which has no global `fetch`.
 *
 * The response body is decoded as UTF-8 unconditionally. That is safe because the only caller,
 * the Extension Data Service, always returns UTF-8 JSON. A server replying with a different
 * charset would not necessarily fail visibly: if the JSON structure itself stays ASCII, a
 * non-UTF-8 byte inside a string value is silently replaced with U+FFFD while `JSON.parse` still
 * succeeds. `Content-Encoding: gzip` is not decoded either, but that failure mode is loud rather
 * than silent: the compressed bytes decode to garbage text that fails `JSON.parse` in
 * `ConfigClient`. Neither charset negotiation nor gzip decoding is implemented on purpose — the
 * single endpoint this talks to needs neither, and either would be surface with no caller.
 */
function performFetch(
  url: string,
  init: { headers: Record<string, string> },
  timeoutMs: number,
  ca: string | Buffer | undefined,
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

    // `ca` is meaningless to the plain `http` transport; only threaded into the request options
    // when there is one to give it, so an http:// URL request is byte-identical to before this
    // option existed.
    const requestOptions: http.RequestOptions | https.RequestOptions =
      ca === undefined ? { method: 'GET', headers: init.headers } : { method: 'GET', headers: init.headers, ca };

    const request = transport.request(
      parsed,
      requestOptions,
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

/**
 * The `httpFetch` this module has always exported: Node's bundled root store, no extra CA.
 * Accepts an optional timeout in milliseconds, beyond the `FetchLike` contract: a function with
 * an extra optional parameter is still structurally assignable wherever a `FetchLike` is expected
 * (e.g. `new ConfigClient({ ..., fetch: httpFetch })`), so `ConfigClient` keeps using the default
 * while tests can pass a short one to stay fast. Kept as its own named function (rather than
 * `createHttpFetch()`'s result) specifically so this three-argument form keeps type-checking at
 * every existing call site — see `createHttpFetch` below for the CA-aware alternative.
 */
export function httpFetch(
  url: string,
  init: { headers: Record<string, string> },
  timeoutMs: number = DEFAULT_TIMEOUT_MS,
): Promise<{ ok: boolean; status: number; text(): Promise<string> }> {
  return performFetch(url, init, timeoutMs, undefined);
}

/**
 * Builds a `FetchLike` closed over an optional CA (and optional default timeout), so a caller
 * that knows the agent's configured CA at startup (see `index.ts`) can hand `ConfigClient` a
 * fetch that trusts it, without `ConfigClient` or `httpFetch` above ever needing to know that CA
 * exists. `createHttpFetch()` with no options behaves like `httpFetch` with its default timeout.
 */
export function createHttpFetch(options: CreateHttpFetchOptions = {}): FetchLike {
  const defaultTimeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  return (url, init) => performFetch(url, init, defaultTimeoutMs, options.ca);
}

// Compile-time proof that httpFetch satisfies the contract ConfigClient actually depends on.
const _satisfiesFetchLike: FetchLike = httpFetch;
void _satisfiesFetchLike;
