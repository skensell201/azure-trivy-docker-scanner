import * as React from 'react';
import { DefaultsConfig } from '../../shared/types';
import { validateDefaults, ValidationIssue } from '../../shared/validation';
import { IssueList } from './IssueList';

export interface DefaultsFormProps {
  defaults: DefaultsConfig;
  onSave: (defaults: DefaultsConfig) => void;
}

/** Splits a comma-separated field into trimmed, non-empty entries. An empty string means "not set". */
function splitList(raw: string): string[] {
  return raw
    .split(',')
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
}

export function DefaultsForm({ defaults, onSave }: DefaultsFormProps): JSX.Element {
  const [dbRepository, setDbRepository] = React.useState(defaults.dbRepository ?? '');
  const [javaDbRepository, setJavaDbRepository] = React.useState(defaults.javaDbRepository ?? '');
  const [dbRegistryUsername, setDbRegistryUsername] = React.useState(
    defaults.dbRegistryUsername ?? '',
  );
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

  // Same treatment as RunnerConfig.registryPassword in RunnerForm: never rendered, carried
  // through untouched unless the administrator explicitly chooses to replace it, so saving a
  // form nobody edited cannot wipe the database mirror's credential out of the settings document.
  const hasStoredPassword = Boolean(defaults.dbRegistryPassword);
  const [replacingPassword, setReplacingPassword] = React.useState(!hasStoredPassword);
  const [newPassword, setNewPassword] = React.useState('');

  const build = (): DefaultsConfig => {
    const next: DefaultsConfig = { dbRepository: dbRepository.trim() };
    if (javaDbRepository.trim()) {
      next.javaDbRepository = javaDbRepository.trim();
    }
    if (cacheDir.trim()) {
      next.cacheDir = cacheDir.trim();
    }
    if (dbRegistryUsername.trim()) {
      next.dbRegistryUsername = dbRegistryUsername.trim();
    }

    const password = replacingPassword ? newPassword : defaults.dbRegistryPassword;
    if (password) {
      next.dbRegistryPassword = password;
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
      <label>
        Database repository
        <input value={dbRepository} onChange={(event) => setDbRepository(event.target.value)} />
      </label>
      <label>
        Java DB repository
        <input
          value={javaDbRepository}
          onChange={(event) => setJavaDbRepository(event.target.value)}
        />
      </label>
      <label>
        Database registry username
        <input
          value={dbRegistryUsername}
          onChange={(event) => setDbRegistryUsername(event.target.value)}
        />
      </label>

      {hasStoredPassword && !replacingPassword ? (
        <div>
          <span>A database registry password is stored.</span>{' '}
          <button type="button" onClick={() => setReplacingPassword(true)}>
            Replace password
          </button>
        </div>
      ) : (
        <label>
          Database registry password
          <input
            type="password"
            value={newPassword}
            onChange={(event) => setNewPassword(event.target.value)}
          />
        </label>
      )}
      <p className="trivy-warning">
        The database registry password is stored in clear text in the extension settings
        document. Anyone with read access to this collection&apos;s extension data can read it.
      </p>

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
