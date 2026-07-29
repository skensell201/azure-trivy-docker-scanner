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

/**
 * Reads administrator-maintained settings documents (runner catalog, global
 * defaults) from the Azure DevOps Extension Data Service.
 */
export class ConfigClient {
  constructor(private readonly options: ConfigClientOptions) {}

  async readDocument<T>(documentId: string): Promise<T | undefined> {
    const base = this.options.collectionUri.replace(/\/+$/, '');
    const url =
      `${base}/_apis/ExtensionManagement/InstalledExtensions/${this.options.publisher}/${this.options.extensionId}` +
      // %24settings is the URL-encoded literal collection name `$settings`
      // used by the Extension Data Service; not a bug.
      `/Data/Scopes/Default/Current/Collections/%24settings/Documents/${documentId}?api-version=${API_VERSION}`;

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

    const document = JSON.parse(await response.text()) as { value: T };
    return document.value;
  }

  private authHeader(): string {
    if (this.options.auth.mode === 'pat') {
      return `Basic ${Buffer.from(`:${this.options.auth.token}`).toString('base64')}`;
    }
    return `Bearer ${this.options.auth.token}`;
  }
}
