import { DatabaseConfig, DefaultsConfig, RunnerConfig } from '../shared/types';

/** The slice of the Extension Data Service this hub needs. Narrow on purpose: it is what the tests fake. */
export interface DocumentManager {
  getDocument(collectionName: string, id: string): Promise<unknown>;
  setDocument(collectionName: string, document: unknown): Promise<unknown>;
}

export class SettingsConflictError extends Error {}

const COLLECTION = '$settings';
const RUNNERS = 'runners';
const DEFAULTS = 'defaults';
const DATABASES = 'databases';

interface StoredDocument<T> {
  id: string;
  __etag: number;
  value: T;
}

function statusOf(error: unknown): number | undefined {
  return (error as { status?: number } | undefined)?.status;
}

export class SettingsStore {
  /** Last etag seen per document, so a save can tell the server which version it edited. */
  private readonly etags = new Map<string, number>();

  constructor(private readonly manager: DocumentManager) {}

  async loadRunners(): Promise<RunnerConfig[]> {
    return (await this.load<RunnerConfig[]>(RUNNERS)) ?? [];
  }

  async loadDefaults(): Promise<DefaultsConfig> {
    return (await this.load<DefaultsConfig>(DEFAULTS)) ?? { dbRepository: '' };
  }

  async saveRunners(runners: RunnerConfig[]): Promise<void> {
    await this.save(RUNNERS, runners);
  }

  async saveDefaults(defaults: DefaultsConfig): Promise<void> {
    await this.save(DEFAULTS, defaults);
  }

  /**
   * A missing `databases` document is an empty catalogue, same reasoning as `loadRunners`: an
   * administrator who has not yet created any custom database entries should see an empty list,
   * not an error, and every runner simply keeps falling back to `DefaultsConfig`'s deprecated
   * fields (see `RunnerConfig.database`'s doc comment).
   */
  async loadDatabases(): Promise<DatabaseConfig[]> {
    return (await this.load<DatabaseConfig[]>(DATABASES)) ?? [];
  }

  async saveDatabases(databases: DatabaseConfig[]): Promise<void> {
    await this.save(DATABASES, databases);
  }

  private async load<T>(id: string): Promise<T | undefined> {
    try {
      const document = (await this.manager.getDocument(COLLECTION, id)) as StoredDocument<T>;
      this.etags.set(id, document.__etag);
      return document.value;
    } catch (error) {
      // A 404 means the administrator has not saved this document yet. Anything else is a real
      // failure and must not be reported as "nothing is configured", or they would recreate
      // settings that already exist.
      if (statusOf(error) === 404) {
        return undefined;
      }
      throw error;
    }
  }

  private async save<T>(id: string, value: T): Promise<void> {
    const document = { id, __etag: this.etags.get(id) ?? -1, value };
    try {
      const stored = (await this.manager.setDocument(COLLECTION, document)) as StoredDocument<T>;
      this.etags.set(id, stored.__etag);
    } catch (error) {
      if (statusOf(error) === 409) {
        // Someone else saved between our read and our write. Drop the stale etag so the next
        // attempt re-reads, and let the caller tell the user rather than clobbering their edit.
        this.etags.delete(id);
        throw new SettingsConflictError(
          'Another administrator changed these settings while you were editing. Reload to see their version, then reapply your change.',
        );
      }
      throw error;
    }
  }
}
