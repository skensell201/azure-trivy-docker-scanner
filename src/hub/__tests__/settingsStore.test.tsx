import { SettingsStore, SettingsConflictError, DocumentManager } from '../settingsStore';
import { DefaultsConfig, RunnerConfig } from '../../shared/types';

const runner = (over: Partial<RunnerConfig> = {}): RunnerConfig => ({
  alias: 'baseline',
  image: 'registry.example.com/trivy:0.58.1',
  isDefault: true,
  enabled: true,
  ...over,
});

class FakeManager implements DocumentManager {
  documents = new Map<string, unknown>();
  setCalls: unknown[] = [];
  conflictOnce = false;

  async getDocument(collection: string, id: string): Promise<unknown> {
    if (!this.documents.has(id)) {
      const error: Error & { status?: number } = new Error('not found');
      error.status = 404;
      throw error;
    }
    return this.documents.get(id);
  }

  async setDocument(collection: string, document: unknown): Promise<unknown> {
    this.setCalls.push(document);
    if (this.conflictOnce) {
      this.conflictOnce = false;
      const error: Error & { status?: number } = new Error('conflict');
      error.status = 409;
      throw error;
    }
    const stored = { ...(document as object), __etag: 5 };
    this.documents.set((document as { id: string }).id, stored);
    return stored;
  }
}

describe('SettingsStore', () => {
  it('returns an empty catalog when the document does not exist yet', async () => {
    const store = new SettingsStore(new FakeManager());
    await expect(store.loadRunners()).resolves.toEqual([]);
  });

  it('returns built-in defaults shape when the defaults document does not exist yet', async () => {
    const store = new SettingsStore(new FakeManager());
    await expect(store.loadDefaults()).resolves.toEqual({ dbRepository: '' });
  });

  it('reads the value out of a stored document', async () => {
    const manager = new FakeManager();
    manager.documents.set('runners', { id: 'runners', __etag: 3, value: [runner()] });
    const store = new SettingsStore(manager);
    await expect(store.loadRunners()).resolves.toEqual([runner()]);
  });

  it('writes the catalog under the runners document id', async () => {
    const manager = new FakeManager();
    const store = new SettingsStore(manager);
    await store.saveRunners([runner()]);
    expect(manager.setCalls[0]).toMatchObject({ id: 'runners', value: [runner()] });
  });

  it('sends etag -1 for a document that does not exist yet', async () => {
    const manager = new FakeManager();
    const store = new SettingsStore(manager);
    await store.saveRunners([runner()]);
    expect(manager.setCalls[0]).toMatchObject({ __etag: -1 });
  });

  it('sends the etag it last read, so a concurrent edit is detected by the server', async () => {
    const manager = new FakeManager();
    manager.documents.set('runners', { id: 'runners', __etag: 7, value: [] });
    const store = new SettingsStore(manager);
    await store.loadRunners();
    await store.saveRunners([runner()]);
    expect(manager.setCalls[0]).toMatchObject({ __etag: 7 });
  });

  it('reports a conflict as SettingsConflictError instead of retrying blindly', async () => {
    const manager = new FakeManager();
    manager.conflictOnce = true;
    const store = new SettingsStore(manager);
    await expect(store.saveRunners([runner()])).rejects.toThrow(SettingsConflictError);
  });

  it('remembers the etag returned by a successful save, so two saves in a row work', async () => {
    const manager = new FakeManager();
    const store = new SettingsStore(manager);
    await store.saveRunners([runner()]);
    await store.saveRunners([runner({ alias: 'hardened' })]);
    expect(manager.setCalls[1]).toMatchObject({ __etag: 5 });
  });

  it('propagates a non-404 read failure rather than pretending nothing is configured', async () => {
    const manager = new FakeManager();
    manager.getDocument = async () => {
      const error: Error & { status?: number } = new Error('boom');
      error.status = 500;
      throw error;
    };
    const store = new SettingsStore(manager);
    await expect(store.loadRunners()).rejects.toThrow(/boom/);
  });

  it('saves defaults under their own document id and etag', async () => {
    const manager = new FakeManager();
    const defaults: DefaultsConfig = { dbRepository: 'registry.example.com/trivy-db:2' };
    const store = new SettingsStore(manager);
    await store.saveDefaults(defaults);
    expect(manager.setCalls[0]).toMatchObject({ id: 'defaults', value: defaults, __etag: -1 });
  });

  it('forgets the stale etag after a conflict, so the next save re-reads instead of clobbering', async () => {
    const manager = new FakeManager();
    manager.documents.set('runners', { id: 'runners', __etag: 7, value: [] });
    const store = new SettingsStore(manager);
    await store.loadRunners();
    manager.conflictOnce = true;
    await expect(store.saveRunners([runner()])).rejects.toThrow(SettingsConflictError);
    await store.saveRunners([runner()]);
    expect(manager.setCalls[1]).toMatchObject({ __etag: -1 });
  });
});
