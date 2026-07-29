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
 * Reads administrator-maintained settings documents (runner catalog, global
 * defaults) from the Azure DevOps Extension Data Service.
 */
export class ConfigClient {
  constructor(private readonly options: ConfigClientOptions) {}

  async readDocument<T>(documentId: string): Promise<T | undefined> {
    const base = this.validatedBase();
    const url =
      `${base}/_apis/ExtensionManagement/InstalledExtensions/${this.options.publisher}/${this.options.extensionId}` +
      // %24settings is the URL-encoded literal collection name `$settings`
      // used by the Extension Data Service; not a bug.
      `/Data/Scopes/Default/Current/Collections/%24settings/Documents/${encodeURIComponent(documentId)}?api-version=${API_VERSION}`;

    let response;
    try {
      response = await this.options.fetch(url, { headers: { Authorization: this.authHeader() } });
    } catch (error) {
      throw new ConfigUnavailableError(
        `Could not reach ${base} to read the "${documentId}" settings document: ${(error as Error).message}`,
      );
    }

    if (response.status === 404) {
      // The administrator has not saved this document yet; that is not an error.
      return undefined;
    }

    if (!response.ok) {
      throw new ConfigUnavailableError(
        `Reading the "${documentId}" settings document failed with HTTP ${response.status}. ` +
          'Enable "Allow scripts to access the OAuth token" on the job, or point the task at a PAT service connection through the configConnection input.',
      );
    }

    const body = await response.text();
    let parsed: unknown;
    try {
      parsed = JSON.parse(body);
    } catch {
      throw new ConfigUnavailableError(
        `The "${documentId}" settings document did not return valid JSON ` +
          `(got: ${body.slice(0, BODY_PREVIEW_LENGTH)}).`,
      );
    }

    if (!hasValueField(parsed)) {
      throw new ConfigUnavailableError(`The "${documentId}" settings document response had no "value" field.`);
    }

    return parsed.value as T;
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
        `System.CollectionUri is not set to a valid http(s) URL (got: "${this.options.collectionUri}").`,
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
