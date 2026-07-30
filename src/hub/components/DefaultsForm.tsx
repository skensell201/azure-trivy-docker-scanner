import * as React from 'react';
import { DefaultsConfig } from '../../shared/types';
import { validateDefaults, ValidationIssue } from '../../shared/validation';
import { IssueList } from './IssueList';

export interface DefaultsFormProps {
  defaults: DefaultsConfig;
  onSave: (defaults: DefaultsConfig) => void;
}

/**
 * Splits a non-empty comma-separated field into trimmed entries. Deliberately does not drop
 * blank entries produced by a stray comma (e.g. "CRITICAL, ,HIGH"): silently discarding them
 * would hide a typo from the administrator. Leaving the empty string in place lets
 * `validateDefaults` reject it as "not a valid severity/scanner", which is its job, not this
 * form's.
 */
function splitList(raw: string): string[] {
  return raw.split(',').map((entry) => entry.trim());
}

export function DefaultsForm({ defaults, onSave }: DefaultsFormProps): JSX.Element {
  const [cacheDir, setCacheDir] = React.useState(defaults.cacheDir ?? '');
  const [skipDbUpdate, setSkipDbUpdate] = React.useState(defaults.skipDbUpdate ?? false);
  const [severities, setSeverities] = React.useState((defaults.severities ?? []).join(','));
  const [scanners, setScanners] = React.useState((defaults.scanners ?? []).join(','));
  const [failOn, setFailOn] = React.useState(defaults.failOn ?? '');
  const [ignoreUnfixed, setIgnoreUnfixed] = React.useState(defaults.ignoreUnfixed ?? false);
  const [timeoutMinutes, setTimeoutMinutes] = React.useState(
    defaults.timeoutMinutes !== undefined ? String(defaults.timeoutMinutes) : '',
  );
  const [issues, setIssues] = React.useState<ValidationIssue[]>([]);

  // `dbRepository`/`javaDbRepository`/`dbRegistryUsername`/`dbRegistryPassword` are deprecated
  // (see DefaultsConfig's doc comment): a database now belongs to a runner via the Databases tab,
  // not to this form. But an administrator who has not yet linked every runner to a cataloged
  // database still depends on whatever is stored here as the fallback, so this form must neither
  // render nor let an unrelated save silently erase it - see `hasLegacyDatabaseSettings` and the
  // unconditional carry-through in `build` below.
  const hasLegacyDatabaseSettings = Boolean(
    defaults.dbRepository ||
      defaults.javaDbRepository ||
      defaults.dbRegistryUsername ||
      defaults.dbRegistryPassword,
  );

  const build = (): DefaultsConfig => {
    const next: DefaultsConfig = {};

    // Carried through untouched: this form has no field for any of these, so there is nothing an
    // administrator could have "edited" here, and saving unrelated defaults must not wipe out the
    // fallback a not-yet-migrated runner still depends on.
    if (defaults.dbRepository !== undefined) {
      next.dbRepository = defaults.dbRepository;
    }
    if (defaults.javaDbRepository !== undefined) {
      next.javaDbRepository = defaults.javaDbRepository;
    }
    if (defaults.dbRegistryUsername !== undefined) {
      next.dbRegistryUsername = defaults.dbRegistryUsername;
    }
    if (defaults.dbRegistryPassword !== undefined) {
      next.dbRegistryPassword = defaults.dbRegistryPassword;
    }

    if (cacheDir.trim()) {
      next.cacheDir = cacheDir.trim();
    }

    if (severities.trim()) {
      next.severities = splitList(severities) as DefaultsConfig['severities'];
    }
    if (scanners.trim()) {
      next.scanners = splitList(scanners) as DefaultsConfig['scanners'];
    }
    if (failOn.trim()) {
      next.failOn = failOn.trim() as DefaultsConfig['failOn'];
    }
    next.skipDbUpdate = skipDbUpdate;
    next.ignoreUnfixed = ignoreUnfixed;

    // An empty field must not become 0: validateDefaults rejects zero, and the administrator
    // would get an error for something they simply left blank.
    if (timeoutMinutes.trim()) {
      next.timeoutMinutes = Number(timeoutMinutes);
    }

    return next;
  };

  const submit = (): void => {
    const candidate = build();
    const found = validateDefaults(candidate);
    setIssues(found);
    if (found.length === 0) {
      onSave(candidate);
    }
  };

  return (
    <div className="trivy-defaults-form">
      {hasLegacyDatabaseSettings ? (
        <p className="trivy-warning trivy-migration-note">
          The database settings have moved to the Databases tab. These values are still being
          used by runners with no database linked, and should be moved there.
        </p>
      ) : null}

      <label>
        Cache directory
        <input value={cacheDir} onChange={(event) => setCacheDir(event.target.value)} />
      </label>
      <label>
        Skip database update
        <input
          type="checkbox"
          checked={skipDbUpdate}
          onChange={(event) => setSkipDbUpdate(event.target.checked)}
        />
      </label>
      <label>
        Severities
        <input value={severities} onChange={(event) => setSeverities(event.target.value)} />
      </label>
      <label>
        Scanners
        <input value={scanners} onChange={(event) => setScanners(event.target.value)} />
      </label>
      <label>
        Fail on
        <input value={failOn} onChange={(event) => setFailOn(event.target.value)} />
      </label>
      <label>
        Ignore unfixed
        <input
          type="checkbox"
          checked={ignoreUnfixed}
          onChange={(event) => setIgnoreUnfixed(event.target.checked)}
        />
      </label>
      <label>
        Timeout (minutes)
        <input
          value={timeoutMinutes}
          onChange={(event) => setTimeoutMinutes(event.target.value)}
        />
      </label>

      <IssueList issues={issues} />

      <button type="button" onClick={submit}>
        Save
      </button>
    </div>
  );
}
