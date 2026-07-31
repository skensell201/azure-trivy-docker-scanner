import * as React from 'react';
import { act, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { App } from '../App';
import { SettingsConflictError } from '../settingsStore';
import { DatabaseConfig, DefaultsConfig, RunnerConfig } from '../../shared/types';

class FakeStore {
  runners: RunnerConfig[] = [
    { alias: 'baseline', image: 'registry.example.com/trivy:0.58.1', isDefault: true, enabled: true },
  ];
  defaults: DefaultsConfig = { dbRepository: 'registry.example.com/trivy-db:2' };
  databases: DatabaseConfig[] = [];
  savedRunners: RunnerConfig[][] = [];
  savedDatabases: DatabaseConfig[][] = [];
  failNextSave: Error | undefined;

  loadRunners = jest.fn(async () => this.runners);
  loadDefaults = jest.fn(async () => this.defaults);
  loadDatabases = jest.fn(async () => this.databases);
  saveRunners = jest.fn(async (runners: RunnerConfig[]) => {
    if (this.failNextSave) {
      const error = this.failNextSave;
      this.failNextSave = undefined;
      throw error;
    }
    this.savedRunners.push(runners);
  });
  saveDefaults = jest.fn(async () => undefined);
  saveDatabases = jest.fn(async (databases: DatabaseConfig[]) => {
    if (this.failNextSave) {
      const error = this.failNextSave;
      this.failNextSave = undefined;
      throw error;
    }
    this.savedDatabases.push(databases);
  });
}

describe('App', () => {
  it('shows the runner catalog once loaded', async () => {
    render(<App store={new FakeStore()} />);
    expect(await screen.findByText('baseline')).toBeTruthy();
  });

  it('offers the four tabs', async () => {
    render(<App store={new FakeStore()} />);
    await screen.findByText('baseline');
    expect(screen.getByRole('tab', { name: /runners/i })).toBeTruthy();
    expect(screen.getByRole('tab', { name: /databases/i })).toBeTruthy();
    expect(screen.getByRole('tab', { name: /defaults/i })).toBeTruthy();
    expect(screen.getByRole('tab', { name: /policy/i })).toBeTruthy();
  });

  it('switches to the defaults tab', async () => {
    render(<App store={new FakeStore()} />);
    await screen.findByText('baseline');
    await userEvent.click(screen.getByRole('tab', { name: /defaults/i }));
    expect(screen.getByLabelText(/cache directory/i)).toBeTruthy();
  });

  it('switches to the databases tab', async () => {
    const store = new FakeStore();
    store.databases = [{ alias: 'official', repository: 'registry.example.com/trivy-db:2' }];
    render(<App store={store} />);
    await screen.findByText('baseline');
    await userEvent.click(screen.getByRole('tab', { name: /databases/i }));
    expect(await screen.findByText('official')).toBeTruthy();
  });

  it('adds a runner and saves the whole catalog', async () => {
    const store = new FakeStore();
    render(<App store={store} />);
    await screen.findByText('baseline');
    await userEvent.click(screen.getByRole('button', { name: /add runner/i }));
    await userEvent.type(screen.getByLabelText(/alias/i), 'hardened');
    await userEvent.type(screen.getByLabelText(/image/i), 'registry.example.com/trivy-fips:0.58.1');
    await act(async () => {
      await userEvent.click(screen.getByRole('button', { name: /^save$/i }));
    });
    await waitFor(() => expect(store.saveRunners).toHaveBeenCalled());
    expect(store.savedRunners[0].map((runner) => runner.alias)).toEqual(['baseline', 'hardened']);
  });

  it('refuses to save a catalog the task would reject', async () => {
    const store = new FakeStore();
    render(<App store={store} />);
    await screen.findByText('baseline');
    await userEvent.click(screen.getByRole('button', { name: /add runner/i }));
    await userEvent.type(screen.getByLabelText(/alias/i), 'hardened');
    await userEvent.type(screen.getByLabelText(/image/i), 'registry.example.com/trivy-fips:0.58.1');
    await userEvent.click(screen.getByLabelText(/default runner/i));
    await userEvent.click(screen.getByRole('button', { name: /^save$/i }));
    await waitFor(() => expect(screen.getByRole('alert').textContent).toMatch(/exactly one/i));
    expect(store.saveRunners).not.toHaveBeenCalled();
  });

  it('tells the administrator when someone else changed the settings', async () => {
    const store = new FakeStore();
    store.failNextSave = new SettingsConflictError('Another administrator changed these settings.');
    render(<App store={store} />);
    await screen.findByText('baseline');
    await act(async () => {
      await userEvent.click(screen.getAllByRole('button', { name: /delete/i })[0]);
    });
    await waitFor(() => expect(screen.getByRole('alert').textContent).toMatch(/another administrator/i));
  });

  it('reports a failed load instead of showing an empty catalog', async () => {
    const store = new FakeStore();
    store.loadRunners = jest.fn(async () => {
      throw new Error('the server said no');
    });
    render(<App store={store} />);
    expect(await screen.findByRole('alert')).toBeTruthy();
    expect(screen.getByRole('alert').textContent).toMatch(/the server said no/);
  });

  it('confirms a successful save', async () => {
    const store = new FakeStore();
    render(<App store={store} />);
    await screen.findByText('baseline');
    await act(async () => {
      await userEvent.click(screen.getAllByRole('button', { name: /delete/i })[0]);
    });
    await waitFor(() => expect(screen.getByText(/saved/i)).toBeTruthy());
  });

  it('deletes the sole runner and warns about the catalog it leaves behind, without blocking the write', async () => {
    const store = new FakeStore();
    render(<App store={store} />);
    await screen.findByText('baseline');
    await act(async () => {
      await userEvent.click(screen.getAllByRole('button', { name: /delete/i })[0]);
    });
    // The write happens unconditionally: an administrator emptying the catalog cannot be
    // trapped by the same rule that blocks an invalid add or edit.
    await waitFor(() => expect(store.saveRunners).toHaveBeenCalledWith([]));
    // The resulting catalog has no default runner, which validateCatalog would reject on the
    // next add/edit - reported as a warning, not the blocking alert used for add/edit failures.
    expect(await screen.findByText(/exactly one/i)).toBeTruthy();
    expect(screen.queryByRole('alert')).toBeNull();
  });

  it('deletes one of several runners with no warning, since the remaining catalog is still valid', async () => {
    const store = new FakeStore();
    store.runners = [
      { alias: 'baseline', image: 'registry.example.com/trivy:0.58.1', isDefault: true, enabled: true },
      { alias: 'legacy', image: 'registry.example.com/trivy:0.44.0', enabled: true },
    ];
    render(<App store={store} />);
    await screen.findByText('legacy');
    await act(async () => {
      await userEvent.click(screen.getAllByRole('button', { name: /delete/i })[1]);
    });
    await waitFor(() =>
      expect(store.saveRunners).toHaveBeenCalledWith([store.runners[0]]),
    );
    expect(await screen.findByText(/saved/i)).toBeTruthy();
    expect(screen.queryByText(/exactly one/i)).toBeNull();
    expect(screen.queryByRole('alert')).toBeNull();
  });

  // --- Databases tab ---

  it('adds a database and saves the whole catalogue', async () => {
    const store = new FakeStore();
    store.databases = [{ alias: 'official', repository: 'registry.example.com/trivy-db:2' }];
    render(<App store={store} />);
    await screen.findByText('baseline');
    await userEvent.click(screen.getByRole('tab', { name: /databases/i }));
    await screen.findByText('official');
    await userEvent.click(screen.getByRole('button', { name: /add database/i }));
    await userEvent.type(screen.getByLabelText('Alias'), 'hardened-db');
    await userEvent.type(screen.getByLabelText(/^repository$/i), 'registry.example.com/trivy-db-fips:2');
    await act(async () => {
      await userEvent.click(screen.getByRole('button', { name: /^save$/i }));
    });
    await waitFor(() => expect(store.saveDatabases).toHaveBeenCalled());
    expect(store.savedDatabases[0].map((database) => database.alias)).toEqual(['official', 'hardened-db']);
  });

  it('never renders a stored database password, and a save that did not touch it keeps it', async () => {
    const store = new FakeStore();
    store.databases = [
      {
        alias: 'official',
        repository: 'registry.example.com/trivy-db:2',
        registryUsername: 'svc',
        registryPassword: 'stored-secret',
      },
    ];
    render(<App store={store} />);
    await screen.findByText('baseline');
    await userEvent.click(screen.getByRole('tab', { name: /databases/i }));
    await screen.findByText('official');
    expect(document.body.innerHTML).not.toContain('stored-secret');

    await userEvent.click(screen.getByRole('button', { name: /edit/i }));
    expect(document.body.innerHTML).not.toContain('stored-secret');
    await act(async () => {
      await userEvent.click(screen.getByRole('button', { name: /^save$/i }));
    });
    await waitFor(() => expect(store.saveDatabases).toHaveBeenCalled());
    expect(store.savedDatabases[0][0]).toMatchObject({ registryPassword: 'stored-secret' });
  });

  it('refuses to delete a database a runner still points at, naming the runner', async () => {
    const store = new FakeStore();
    store.runners = [
      {
        alias: 'baseline',
        image: 'registry.example.com/trivy:0.58.1',
        isDefault: true,
        enabled: true,
        database: 'official',
      },
    ];
    store.databases = [{ alias: 'official', repository: 'registry.example.com/trivy-db:2' }];
    render(<App store={store} />);
    await screen.findByText('baseline');
    await userEvent.click(screen.getByRole('tab', { name: /databases/i }));
    await screen.findByText('official');
    await act(async () => {
      await userEvent.click(screen.getByRole('button', { name: /delete/i }));
    });
    await waitFor(() => expect(screen.getByRole('alert')).toBeTruthy());
    expect(screen.getByRole('alert').textContent).toMatch(/baseline/);
    expect(store.saveDatabases).not.toHaveBeenCalled();
  });

  it('lets a database with no runner pointing at it be deleted', async () => {
    const store = new FakeStore();
    store.databases = [{ alias: 'official', repository: 'registry.example.com/trivy-db:2' }];
    render(<App store={store} />);
    await screen.findByText('baseline');
    await userEvent.click(screen.getByRole('tab', { name: /databases/i }));
    await screen.findByText('official');
    await act(async () => {
      await userEvent.click(screen.getByRole('button', { name: /delete/i }));
    });
    await waitFor(() => expect(store.saveDatabases).toHaveBeenCalledWith([]));
    expect(screen.queryByRole('alert')).toBeNull();
  });

  it('refuses to save a runner naming a database that no longer exists, since the two documents can disagree', async () => {
    const store = new FakeStore();
    store.runners = [
      {
        alias: 'baseline',
        image: 'registry.example.com/trivy:0.58.1',
        isDefault: true,
        enabled: true,
        database: 'missing-db',
      },
    ];
    store.databases = [];
    render(<App store={store} />);
    await screen.findByText('baseline');
    await userEvent.click(screen.getByRole('button', { name: /edit/i }));
    await act(async () => {
      await userEvent.click(screen.getByRole('button', { name: /^save$/i }));
    });
    await waitFor(() => expect(screen.getByRole('alert')).toBeTruthy());
    expect(screen.getByRole('alert').textContent).toMatch(/missing-db/);
    expect(screen.getByRole('alert').textContent).toMatch(/baseline/);
    expect(store.saveRunners).not.toHaveBeenCalled();
  });

  it('offers the database catalogue and the not-linked option when adding a runner', async () => {
    const store = new FakeStore();
    store.databases = [{ alias: 'official', repository: 'registry.example.com/trivy-db:2' }];
    render(<App store={store} />);
    await screen.findByText('baseline');
    await userEvent.click(screen.getByRole('button', { name: /add runner/i }));
    const select = screen.getByLabelText('Database') as HTMLSelectElement;
    const values = Array.from(select.options).map((option) => option.value);
    expect(values).toEqual(['', 'official']);
  });

  // --- Summary line ---

  it('summarizes runner, database and unlinked counts, and how many policy fields are locked', async () => {
    const store = new FakeStore();
    store.runners = [
      { alias: 'baseline', image: 'registry.example.com/trivy:0.58.1', isDefault: true, enabled: true },
      { alias: 'legacy', image: 'registry.example.com/trivy:0.44.0', enabled: true },
    ];
    store.databases = [{ alias: 'official', repository: 'registry.example.com/trivy-db:2' }];
    // No allowOverrides at all means every one of the ten fields is allowed, so none are locked.
    store.defaults = { dbRepository: '' };
    render(<App store={store} />);
    await screen.findByText('baseline');

    expect(screen.getByText(/^2 runners$/)).toBeTruthy();
    expect(screen.getByText(/^1 database$/)).toBeTruthy();
    // Neither runner names a database, so both are unlinked.
    expect(screen.getByText(/2 runners unlinked/)).toBeTruthy();
    expect(screen.getByText(/0\/10 policy fields locked/)).toBeTruthy();
  });

  it('shows zero unlinked runners once every runner names a database, without warning styling', async () => {
    const store = new FakeStore();
    store.runners = [
      {
        alias: 'baseline',
        image: 'registry.example.com/trivy:0.58.1',
        isDefault: true,
        enabled: true,
        database: 'official',
      },
    ];
    store.databases = [{ alias: 'official', repository: 'registry.example.com/trivy-db:2' }];
    render(<App store={store} />);
    await screen.findByText('baseline');

    const unlinkedStat = screen.getByText(/0 runners unlinked/);
    expect(unlinkedStat).toBeTruthy();
    expect(unlinkedStat.className).not.toMatch(/warn/i);
  });

  it('marks the unlinked count with a warning style when it is not zero', async () => {
    const store = new FakeStore();
    // store.runners already has one runner with no `database` set.
    render(<App store={store} />);
    await screen.findByText('baseline');

    const unlinkedStat = screen.getByText(/1 runner unlinked/);
    expect(unlinkedStat.className).toMatch(/warn/i);
  });

  it('counts locked policy fields from an explicit allowOverrides list', async () => {
    const store = new FakeStore();
    store.defaults = { dbRepository: '', allowOverrides: ['severities', 'failOn'] };
    render(<App store={store} />);
    await screen.findByText('baseline');

    // Ten overridable fields total, two allowed, so eight are locked.
    expect(screen.getByText(/8\/10 policy fields locked/)).toBeTruthy();
  });

  it('counts every policy field as locked when allowOverrides is an explicit empty list', async () => {
    const store = new FakeStore();
    store.defaults = { dbRepository: '', allowOverrides: [] };
    render(<App store={store} />);
    await screen.findByText('baseline');

    expect(screen.getByText(/10\/10 policy fields locked/)).toBeTruthy();
  });

  it('saves the database selected on the runner form', async () => {
    const store = new FakeStore();
    store.databases = [{ alias: 'official', repository: 'registry.example.com/trivy-db:2' }];
    render(<App store={store} />);
    await screen.findByText('baseline');
    await userEvent.click(screen.getByRole('button', { name: /add runner/i }));
    await userEvent.type(screen.getByLabelText(/alias/i), 'hardened');
    await userEvent.type(screen.getByLabelText(/image/i), 'registry.example.com/trivy-fips:0.58.1');
    await userEvent.selectOptions(screen.getByLabelText('Database'), 'official');
    await act(async () => {
      await userEvent.click(screen.getByRole('button', { name: /^save$/i }));
    });
    await waitFor(() => expect(store.saveRunners).toHaveBeenCalled());
    expect(store.savedRunners[0][1]).toMatchObject({ database: 'official' });
  });

  // --- Operations console: list on the left, detail pane on the right ---

  it('opens the selected runner in the detail pane, prefilled with its own values', async () => {
    const store = new FakeStore();
    store.runners = [
      { alias: 'baseline', image: 'registry.example.com/trivy:0.58.1', isDefault: true, enabled: true },
      { alias: 'legacy', image: 'registry.example.com/trivy:0.44.0', enabled: true },
    ];
    render(<App store={store} />);
    await screen.findByText('legacy');
    await userEvent.click(screen.getByRole('button', { name: /edit legacy/i }));
    expect((screen.getByLabelText('Alias') as HTMLInputElement).value).toBe('legacy');
    expect((screen.getByLabelText('Image') as HTMLInputElement).value).toBe(
      'registry.example.com/trivy:0.44.0',
    );
  });

  it('keeps the runner list visible while the detail pane is open', async () => {
    const store = new FakeStore();
    store.runners = [
      { alias: 'baseline', image: 'registry.example.com/trivy:0.58.1', isDefault: true, enabled: true },
      { alias: 'legacy', image: 'registry.example.com/trivy:0.44.0', enabled: true },
    ];
    render(<App store={store} />);
    await screen.findByText('legacy');
    await userEvent.click(screen.getByRole('button', { name: /edit legacy/i }));
    // The pane is open (its own fields are visible)...
    expect(screen.getByLabelText('Alias')).toBeTruthy();
    // ...and the list, including the row not being edited, is still on screen.
    expect(screen.getByText('baseline')).toBeTruthy();
    expect(screen.getByText('legacy')).toBeTruthy();
  });

  it('saves an edit made in the pane as part of the whole catalog, leaving the other runner untouched', async () => {
    const store = new FakeStore();
    store.runners = [
      { alias: 'baseline', image: 'registry.example.com/trivy:0.58.1', isDefault: true, enabled: true },
      { alias: 'legacy', image: 'registry.example.com/trivy:0.44.0', enabled: true },
    ];
    render(<App store={store} />);
    await screen.findByText('legacy');
    await userEvent.click(screen.getByRole('button', { name: /edit legacy/i }));
    await userEvent.clear(screen.getByLabelText('Image'));
    await userEvent.type(screen.getByLabelText('Image'), 'registry.example.com/trivy:0.50.0');
    await act(async () => {
      await userEvent.click(screen.getByRole('button', { name: /^save$/i }));
    });
    await waitFor(() => expect(store.saveRunners).toHaveBeenCalled());
    expect(store.savedRunners[0]).toEqual([
      store.runners[0],
      expect.objectContaining({ alias: 'legacy', image: 'registry.example.com/trivy:0.50.0' }),
    ]);
  });

  it('shows the deprecated-Defaults warning chip for an unlinked runner, and the database alias for a linked one, in the list itself', async () => {
    const store = new FakeStore();
    store.runners = [
      {
        alias: 'baseline',
        image: 'registry.example.com/trivy:0.58.1',
        isDefault: true,
        enabled: true,
        database: 'official',
      },
      { alias: 'legacy', image: 'registry.example.com/trivy:0.44.0', enabled: true },
    ];
    store.databases = [{ alias: 'official', repository: 'registry.example.com/trivy-db:2' }];
    render(<App store={store} />);
    await screen.findByText('legacy');

    const linkedRow = screen.getByText('baseline').closest('li');
    expect(linkedRow?.textContent).toMatch(/official/);

    const unlinkedRow = screen.getByText('legacy').closest('li');
    expect(unlinkedRow?.textContent).toMatch(/deprecated Defaults settings/i);
  });
});
