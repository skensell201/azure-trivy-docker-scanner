import * as React from 'react';
import './hub.css';
import { DefaultsConfig, RunnerConfig } from '../shared/types';
import { validateCatalog, validateRunner, ValidationIssue } from '../shared/validation';
import { SettingsConflictError } from './settingsStore';
import { RunnerTable } from './components/RunnerTable';
import { RunnerForm } from './components/RunnerForm';
import { DefaultsForm } from './components/DefaultsForm';
import { PolicyForm } from './components/PolicyForm';
import { IssueList } from './components/IssueList';

/**
 * The slice of `SettingsStore` this shell needs. `SettingsStore` satisfies this structurally;
 * it is not implemented via an interface/class relationship, so a fake store in tests needs
 * nothing beyond these four methods.
 */
export interface SettingsGateway {
  loadRunners(): Promise<RunnerConfig[]>;
  loadDefaults(): Promise<DefaultsConfig>;
  saveRunners(runners: RunnerConfig[]): Promise<void>;
  saveDefaults(defaults: DefaultsConfig): Promise<void>;
}

export interface AppProps {
  store: SettingsGateway;
}

type Tab = 'runners' | 'defaults' | 'policy';

export function App({ store }: AppProps): JSX.Element {
  const [runners, setRunners] = React.useState<RunnerConfig[] | undefined>(undefined);
  const [defaults, setDefaults] = React.useState<DefaultsConfig | undefined>(undefined);
  const [tab, setTab] = React.useState<Tab>('runners');
  const [editing, setEditing] = React.useState<RunnerConfig | undefined | 'new'>(undefined);
  const [loadError, setLoadError] = React.useState<string | undefined>(undefined);
  const [issues, setIssues] = React.useState<ValidationIssue[]>([]);
  const [savedMessage, setSavedMessage] = React.useState<string | undefined>(undefined);

  React.useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const [loadedRunners, loadedDefaults] = await Promise.all([
          store.loadRunners(),
          store.loadDefaults(),
        ]);
        if (cancelled) {
          return;
        }
        setRunners(loadedRunners);
        setDefaults(loadedDefaults);
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

  /** Writes a runner catalog and reflects the outcome, without deciding whether it is valid. */
  const writeRunners = async (next: RunnerConfig[]): Promise<void> => {
    try {
      await store.saveRunners(next);
      setRunners(next);
      setSavedMessage('Saved.');
      setIssues([]);
    } catch (error) {
      if (error instanceof SettingsConflictError) {
        setIssues([{ field: 'runners', message: error.message }]);
        return;
      }
      setIssues([{ field: 'runners', message: (error as Error).message }]);
    }
  };

  /**
   * Validates the whole catalog (cross-runner invariants) plus each individual runner (shape of
   * a single entry) before writing. Either check can fail on a hand-edited document even when
   * the form that produced this particular change was itself valid, so both must run here, not
   * just inside RunnerForm. Used for add/edit, where the modal introduces a runner the rest of
   * the catalog has never seen; deleting an existing, already-valid runner writes immediately
   * (see `handleDeleteRunner`) instead of going through this gate.
   */
  const persistRunners = async (next: RunnerConfig[]): Promise<void> => {
    const found = [...validateCatalog(next), ...next.flatMap((runner) => validateRunner(runner))];
    if (found.length > 0) {
      setIssues(found);
      return;
    }
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

  const handleDeleteRunner = async (runner: RunnerConfig): Promise<void> => {
    const next = (runners ?? []).filter((existing) => existing !== runner);
    await writeRunners(next);
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

  if (loadError !== undefined) {
    return (
      <div role="alert">
        Could not load settings: {loadError}
      </div>
    );
  }

  if (runners === undefined || defaults === undefined) {
    return <p>Loading…</p>;
  }

  return (
    <div className="trivy-hub">
      <div role="tablist">
        <button role="tab" aria-selected={tab === 'runners'} onClick={() => setTab('runners')}>
          Runners
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

      {tab === 'runners' ? (
        editing !== undefined ? (
          <RunnerForm
            runner={editing === 'new' ? undefined : editing}
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
