export class ConfigUnavailableError extends Error {}

export type AuthMode = 'bearer' | 'pat';

/**
 * Minimal fetch surface the client depends on. Kept separate from the global
 * `fetch` type because build agents may run on Node 16, where no global
 * fetch exists; a later task supplies an implementation built on `https`.
 */
export interface FetchLike {
  (url: string, init: { headers: Record<string, string> }): Promise<{
    ok: boolean;
    status: number;
    text(): Promise<string>;
  }>;
}

export interface ConfigClientOptions {
  collectionUri: string;
  publisher: string;
  extensionId: string;
  auth: { mode: AuthMode; token: string };
  fetch: FetchLike;
  /**
   * Optional informational logging hook. Invoked (at most once per call) when
   * a 404 causes readDocument to fall back to undefined, so a mistyped
   * publisher/extensionId or an administrator who never saved the document
   * leaves a trace instead of silently degrading to defaults.
   */
  log?: (message: string) => void;
}

const API_VERSION = '3.2-preview.1';

// Only this many characters of a malformed body are echoed back in an error
// message: enough to recognize "this is an HTML sign-in page", not enough to
// dump an entire unexpected response into the pipeline log.
const BODY_PREVIEW_LENGTH = 200;

function hasValueField(parsed: unknown): parsed is { value: unknown } {
  return typeof parsed === 'object' && parsed !== null && 'value' in parsed;
}

/**
 * Strips `user:pass@` userinfo from the front of a URL before it is ever put
 * in a message shown to a human (log line or thrown error). The credentials
 * are still sent to `fetch` untouched - only messages are redacted.
 */
function redactUserinfo(url: string): string {
  return url.replace(/^(\w+:\/\/)[^/@]*@/i, '$1');
}

/**
 * Builds a diagnostic preview of a response body that is safe to interpolate
 * into a message which may end up echoed to a pipeline console:
 * - cut by Unicode code point (not UTF-16 code unit), so a surrogate pair
 *   straddling the cut is never split into a lone, invalid surrogate;
 * - control characters (including raw newlines/CR and NUL) collapsed to
 *   spaces, so the body cannot inject fake log lines or corrupt the terminal;
 * - the Azure Pipelines "##vso[" logging-command marker broken up, so a
 *   response body cannot forge a pipeline command when this message is later
 *   logged.
 */
function previewBody(body: string): string {
  const truncated = Array.from(body).slice(0, BODY_PREVIEW_LENGTH).join('');
  // eslint-disable-next-line no-control-regex -- deliberately matching C0/DEL control characters
  const withoutControlChars = truncated.replace(/[\x00-\x1f\x7f]/g, ' ');
  return withoutControlChars.replace(/##vso\[/gi, '# #vso[');
}

/**
 * Reads administrator-maintained settings documents (runner catalog, global
 * defaults) from the Azure DevOps Extension Data Service.
 */
export class ConfigClient {
  constructor(private readonly options: ConfigClientOptions) {}

  async readDocument<T>(documentId: string): Promise<T | null | undefined> {
    const base = this.validatedBase();
    const url =
      `${base}/_apis/ExtensionManagement/InstalledExtensions/${encodeURIComponent(this.options.publisher)}/${encodeURIComponent(this.options.extensionId)}` +
      // %24settings is the URL-encoded literal collection name `$settings`
      // used by the Extension Data Service; not a bug.
      `/Data/Scopes/Default/Current/Collections/%24settings/Documents/${encodeURIComponent(documentId)}?api-version=${API_VERSION}`;

    let response;
    try {
      response = await this.options.fetch(url, { headers: { Authorization: this.authHeader() } });
    } catch (error) {
      throw new ConfigUnavailableError(
        `Could not reach ${redactUserinfo(base)} to read the "${documentId}" settings document: ${(error as Error).message}`,
      );
    }

    if (response.status === 404) {
      // The administrator has not saved this document yet; that is not an error,
      // but it is indistinguishable from a mistyped publisher/extensionId
      // without a trace, so log it rather than fail silently.
      this.options.log?.(
        `Settings document "${documentId}" was not found at ${redactUserinfo(url)}; continuing without it.`,
      );
      return undefined;
    }

    if (!response.ok) {
      throw new ConfigUnavailableError(
        `Reading the "${documentId}" settings document failed with HTTP ${response.status}. ` +
          'Enable "Allow scripts to access the OAuth token" on the job, or point the task at a PAT service connection through the configConnection input.',
      );
    }

    let body: string | undefined;
    let parsed: unknown;
    try {
      body = await response.text();
      parsed = JSON.parse(body);
    } catch (error) {
      throw new ConfigUnavailableError(
        body === undefined
          ? `Reading the "${documentId}" settings document response failed: ${(error as Error).message}`
          : `The "${documentId}" settings document did not return valid JSON (got: ${previewBody(body)}).`,
      );
    }

    if (!hasValueField(parsed)) {
      throw new ConfigUnavailableError(`The "${documentId}" settings document response had no "value" field.`);
    }

    return parsed.value as T | null;
  }

  /**
   * collectionUri comes from System.CollectionUri (or an equivalent input);
   * validating it here, before ever calling fetch, means a misconfigured
   * pipeline gets a message naming that variable instead of a generic
   * connection failure against a hostless URL.
   */
  private validatedBase(): string {
    const base = this.options.collectionUri.replace(/\/+$/, '');
    if (!/^https?:\/\/.+/i.test(base)) {
      throw new ConfigUnavailableError(
        `System.CollectionUri is not set to a valid http(s) URL (got: "${redactUserinfo(this.options.collectionUri)}").`,
      );
    }
    return base;
  }

  private authHeader(): string {
    if (this.options.auth.mode === 'pat') {
      return `Basic ${Buffer.from(`:${this.options.auth.token}`).toString('base64')}`;
    }
    return `Bearer ${this.options.auth.token}`;
  }
}
