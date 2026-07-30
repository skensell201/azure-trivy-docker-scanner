import * as React from 'react';
import './hub.css';
import { DatabaseConfig, DefaultsConfig, RunnerConfig } from '../shared/types';
import {
  validateCatalog,
  validateDatabase,
  validateDatabaseCatalogue,
  validateRunner,
  validateRunnerDatabaseLinks,
  ValidationIssue,
} from '../shared/validation';
import { SettingsConflictError } from './settingsStore';
import { RunnerTable } from './components/RunnerTable';
import { RunnerForm } from './components/RunnerForm';
import { DatabaseTable } from './components/DatabaseTable';
import { DatabaseForm } from './components/DatabaseForm';
import { DefaultsForm } from './components/DefaultsForm';
import { PolicyForm } from './components/PolicyForm';
import { IssueList } from './components/IssueList';

/**
 * The slice of `SettingsStore` this shell needs. `SettingsStore` satisfies this structurally;
 * it is not implemented via an interface/class relationship, so a fake store in tests needs
 * nothing beyond these six methods.
 */
export interface SettingsGateway {
  loadRunners(): Promise<RunnerConfig[]>;
  loadDefaults(): Promise<DefaultsConfig>;
  loadDatabases(): Promise<DatabaseConfig[]>;
  saveRunners(runners: RunnerConfig[]): Promise<void>;
  saveDefaults(defaults: DefaultsConfig): Promise<void>;
  saveDatabases(databases: DatabaseConfig[]): Promise<void>;
}

export interface AppProps {
  store: SettingsGateway;
}

type Tab = 'runners' | 'databases' | 'defaults' | 'policy';

/**
 * `validateRunnerDatabaseLinks` names an offending runner only by array index
 * (`runners[N].database`), agnostic of aliases since it does not know which document layout
 * called it. Only here, where both documents are in hand, can the message be made to actually
 * name the runner an administrator would recognize - so this rewrites the field-indexed message
 * into one that leads with the runner's alias, for every issue this shell surfaces.
 */
function nameRunnersInLinkIssues(issues: ValidationIssue[], runners: RunnerConfig[]): ValidationIssue[] {
  return issues.map((issue) => {
    const match = /^runners\[(\d+)\]\.database$/.exec(issue.field);
    if (!match) {
      return issue;
    }
    const alias = runners[Number(match[1])]?.alias;
    return alias ? { ...issue, message: `Runner "${alias}": ${issue.message}` } : issue;
  });
}

export function App({ store }: AppProps): JSX.Element {
  const [runners, setRunners] = React.useState<RunnerConfig[] | undefined>(undefined);
  const [defaults, setDefaults] = React.useState<DefaultsConfig | undefined>(undefined);
  const [databases, setDatabases] = React.useState<DatabaseConfig[] | undefined>(undefined);
  const [tab, setTab] = React.useState<Tab>('runners');
  const [editing, setEditing] = React.useState<RunnerConfig | undefined | 'new'>(undefined);
  const [editingDatabase, setEditingDatabase] = React.useState<DatabaseConfig | undefined | 'new'>(undefined);
  const [loadError, setLoadError] = React.useState<string | undefined>(undefined);
  const [issues, setIssues] = React.useState<ValidationIssue[]>([]);
  const [savedMessage, setSavedMessage] = React.useState<string | undefined>(undefined);
  // Cross-runner problems found in a catalog that was already written by a delete (see
  // handleDeleteRunner). Deliberately a separate piece of state from `issues`: those are
  // blocking - add/edit never reaches the store while they are non-empty - while this one
  // describes a write that already happened and cannot be undone by refusing it.
  const [catalogWarning, setCatalogWarning] = React.useState<ValidationIssue[]>([]);

  React.useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const [loadedRunners, loadedDefaults, loadedDatabases] = await Promise.all([
          store.loadRunners(),
          store.loadDefaults(),
          store.loadDatabases(),
        ]);
        if (cancelled) {
          return;
        }
        setRunners(loadedRunners);
        setDefaults(loadedDefaults);
        setDatabases(loadedDatabases);
      } catch (error) {
        if (cancelled) {
          return;
        }
        // A failed load must not be rendered as an empty catalog: that would invite an
        // administrator to recreate settings that already exist on the server.
        setLoadError((error as Error).message);
      }
    })();
    return () => {
      cancelled = true;
    };
    // `store` is a stable prop for the lifetime of this component, so this effect intentionally
    // runs once on mount rather than re-running on every render.
  }, []);

  /**
   * Writes a runner catalog and reflects the outcome, without deciding whether it is valid.
   * Returns whether the write actually landed, so callers that care - see `handleDeleteRunner` -
   * can tell a real save from a rejected one.
   */
  const writeRunners = async (next: RunnerConfig[]): Promise<boolean> => {
    try {
      await store.saveRunners(next);
      setRunners(next);
      setSavedMessage('Saved.');
      setIssues([]);
      return true;
    } catch (error) {
      if (error instanceof SettingsConflictError) {
        setIssues([{ field: 'runners', message: error.message }]);
        return false;
      }
      setIssues([{ field: 'runners', message: (error as Error).message }]);
      return false;
    }
  };

  /**
   * Validates the whole catalog (cross-runner invariants), each individual runner (shape of a
   * single entry), and every runner's link into the database catalogue before writing. All three
   * can fail on a hand-edited document even when the form that produced this particular change
   * was itself valid, so all three must run here, not just inside RunnerForm - the link check
   * especially, since only this shell holds both documents at once (see
   * `nameRunnersInLinkIssues`'s doc comment). Used for add/edit, where the modal introduces a
   * runner the rest of the catalog has never seen; deleting an existing, already-valid runner
   * writes immediately (see `handleDeleteRunner`) instead of going through this gate.
   */
  const persistRunners = async (next: RunnerConfig[]): Promise<void> => {
    const found = [
      ...validateCatalog(next),
      ...next.flatMap((runner) => validateRunner(runner)),
      ...nameRunnersInLinkIssues(validateRunnerDatabaseLinks(next, databases ?? []), next),
    ];
    if (found.length > 0) {
      setIssues(found);
      return;
    }
    // A validated add/edit write can only ever produce a catalog validateCatalog accepts, so any
    // warning left over from an earlier delete no longer applies.
    setCatalogWarning([]);
    await writeRunners(next);
  };

  const handleSaveRunner = async (runner: RunnerConfig): Promise<void> => {
    const current = runners ?? [];
    const next =
      editing !== 'new' && editing !== undefined
        ? current.map((existing) => (existing === editing ? runner : existing))
        : [...current, runner];
    setEditing(undefined);
    await persistRunners(next);
  };

  /**
   * Deletion must always be able to proceed, even down to a catalog `validateCatalog` would
   * reject - e.g. no runners left, or no default among what remains - because an administrator
   * legitimately emptying the catalog cannot be trapped by the same rule that blocks an invalid
   * add or edit. So the write happens unconditionally, and only afterwards is the resulting
   * catalog checked; any problem is shown as a non-blocking warning, in its own element, never
   * inside the `role="alert"` IssueList used for blocking add/edit errors, so the two cannot be
   * confused by a test or by an administrator skimming the page.
   */
  const handleDeleteRunner = async (runner: RunnerConfig): Promise<void> => {
    const next = (runners ?? []).filter((existing) => existing !== runner);
    const saved = await writeRunners(next);
    setCatalogWarning(saved ? validateCatalog(next) : []);
  };

  const handleSaveDefaults = async (next: DefaultsConfig): Promise<void> => {
    try {
      await store.saveDefaults(next);
      setDefaults(next);
      setSavedMessage('Saved.');
      setIssues([]);
    } catch (error) {
      if (error instanceof SettingsConflictError) {
        setIssues([{ field: 'defaults', message: error.message }]);
        return;
      }
      setIssues([{ field: 'defaults', message: (error as Error).message }]);
    }
  };

  /** Writes a database catalogue and reflects the outcome, same shape as `writeRunners`. */
  const writeDatabases = async (next: DatabaseConfig[]): Promise<boolean> => {
    try {
      await store.saveDatabases(next);
      setDatabases(next);
      setSavedMessage('Saved.');
      setIssues([]);
      return true;
    } catch (error) {
      if (error instanceof SettingsConflictError) {
        setIssues([{ field: 'databases', message: error.message }]);
        return false;
      }
      setIssues([{ field: 'databases', message: (error as Error).message }]);
      return false;
    }
  };

  /**
   * Validates the whole catalogue, each individual database, and - since a database being
   * renamed or removed here can orphan a runner's link just as surely as deleting it outright
   * (see `handleDeleteDatabase`) - every runner's link into the resulting catalogue, before
   * writing. Unlike runner deletion, there is no "write unconditionally, warn afterwards" path
   * for databases: a runner losing its database silently would leave a scan quietly falling back
   * to defaults nobody meant it to use, so this is always a blocking refusal.
   */
  const persistDatabases = async (next: DatabaseConfig[]): Promise<void> => {
    const found = [
      ...validateDatabaseCatalogue(next),
      ...next.flatMap((database) => validateDatabase(database)),
      ...nameRunnersInLinkIssues(validateRunnerDatabaseLinks(runners ?? [], next), runners ?? []),
    ];
    if (found.length > 0) {
      setIssues(found);
      return;
    }
    await writeDatabases(next);
  };

  const handleSaveDatabase = async (database: DatabaseConfig): Promise<void> => {
    const current = databases ?? [];
    const next =
      editingDatabase !== 'new' && editingDatabase !== undefined
        ? current.map((existing) => (existing === editingDatabase ? database : existing))
        : [...current, database];
    setEditingDatabase(undefined);
    await persistDatabases(next);
  };

  /**
   * Unlike `handleDeleteRunner`, this refuses rather than writing-then-warning: deleting a
   * database out from under a runner that still names it would silently switch that runner onto
   * the deprecated `DefaultsConfig` fallback (see `RunnerConfig.database`'s doc comment), which is
   * exactly the kind of surprise `validateRunnerDatabaseLinks` exists to prevent - so the write
   * never happens while any runner still points here.
   */
  const handleDeleteDatabase = async (database: DatabaseConfig): Promise<void> => {
    const next = (databases ?? []).filter((existing) => existing !== database);
    const linkIssues = nameRunnersInLinkIssues(
      validateRunnerDatabaseLinks(runners ?? [], next),
      runners ?? [],
    );
    if (linkIssues.length > 0) {
      setIssues(linkIssues);
      return;
    }
    await writeDatabases(next);
  };

  if (loadError !== undefined) {
    return (
      <div role="alert">
        Could not load settings: {loadError}
      </div>
    );
  }

  if (runners === undefined || defaults === undefined || databases === undefined) {
    return <p role="status">Loading…</p>;
  }

  return (
    <div className="trivy-hub">
      <div role="tablist">
        <button role="tab" aria-selected={tab === 'runners'} onClick={() => setTab('runners')}>
          Runners
        </button>
        <button role="tab" aria-selected={tab === 'databases'} onClick={() => setTab('databases')}>
          Databases
        </button>
        <button role="tab" aria-selected={tab === 'defaults'} onClick={() => setTab('defaults')}>
          Defaults
        </button>
        <button role="tab" aria-selected={tab === 'policy'} onClick={() => setTab('policy')}>
          Policy
        </button>
      </div>

      {savedMessage !== undefined ? <p>{savedMessage}</p> : null}
      <IssueList issues={issues} />
      {catalogWarning.length > 0 ? (
        <div role="status" className="trivy-warning trivy-catalog-warning">
          {catalogWarning.map((issue) => (
            <div key={`${issue.field}:${issue.message}`}>
              <strong>Warning:</strong> {issue.message}
            </div>
          ))}
        </div>
      ) : null}

      {tab === 'runners' ? (
        editing !== undefined ? (
          <RunnerForm
            runner={editing === 'new' ? undefined : editing}
            databases={databases}
            onSave={(runner) => {
              void handleSaveRunner(runner);
            }}
            onCancel={() => setEditing(undefined)}
          />
        ) : (
          <>
            <button type="button" onClick={() => setEditing('new')}>
              Add runner
            </button>
            <RunnerTable
              runners={runners}
              onEdit={(runner) => setEditing(runner)}
              onDelete={(runner) => {
                void handleDeleteRunner(runner);
              }}
            />
          </>
        )
      ) : null}

      {tab === 'databases' ? (
        editingDatabase !== undefined ? (
          <DatabaseForm
            database={editingDatabase === 'new' ? undefined : editingDatabase}
            onSave={(database) => {
              void handleSaveDatabase(database);
            }}
            onCancel={() => setEditingDatabase(undefined)}
          />
        ) : (
          <>
            <button type="button" onClick={() => setEditingDatabase('new')}>
              Add database
            </button>
            <DatabaseTable
              databases={databases}
              onEdit={(database) => setEditingDatabase(database)}
              onDelete={(database) => {
                void handleDeleteDatabase(database);
              }}
            />
          </>
        )
      ) : null}

      {tab === 'defaults' ? (
        <DefaultsForm
          defaults={defaults}
          onSave={(next) => {
            void handleSaveDefaults(next);
          }}
        />
      ) : null}

      {tab === 'policy' ? (
        <PolicyForm
          defaults={defaults}
          onSave={(next) => {
            void handleSaveDefaults(next);
          }}
        />
      ) : null}
    </div>
  );
}
