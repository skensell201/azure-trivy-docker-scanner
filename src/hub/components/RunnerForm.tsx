import * as React from 'react';
import { RunnerConfig } from '../../shared/types';
import { validateRunner, ValidationIssue } from '../../shared/validation';
import { IssueList } from './IssueList';

export interface RunnerFormProps {
  /** Undefined when adding; the existing runner when editing. */
  runner: RunnerConfig | undefined;
  onSave: (runner: RunnerConfig) => void;
  onCancel: () => void;
}

export function RunnerForm({ runner, onSave, onCancel }: RunnerFormProps): JSX.Element {
  const [alias, setAlias] = React.useState(runner?.alias ?? '');
  const [image, setImage] = React.useState(runner?.image ?? '');
  const [displayName, setDisplayName] = React.useState(runner?.displayName ?? '');
  const [description, setDescription] = React.useState(runner?.description ?? '');
  const [extraDockerArgs, setExtraDockerArgs] = React.useState(runner?.extraDockerArgs ?? '');
  const [registryUsername, setRegistryUsername] = React.useState(runner?.registryUsername ?? '');
  const [isDefault, setIsDefault] = React.useState(runner?.isDefault ?? false);
  const [enabled, setEnabled] = React.useState(runner?.enabled !== false);
  const [issues, setIssues] = React.useState<ValidationIssue[]>([]);

  // The stored password is never rendered. It is only carried through untouched unless the
  // administrator explicitly chooses to replace it, so saving a form nobody edited cannot
  // wipe the credential out of the settings document.
  const hasStoredPassword = Boolean(runner?.registryPassword);
  const [replacingPassword, setReplacingPassword] = React.useState(!hasStoredPassword);
  const [newPassword, setNewPassword] = React.useState('');

  const build = (): RunnerConfig => {
    const next: RunnerConfig = { alias: alias.trim(), image: image.trim(), isDefault, enabled };
    if (displayName.trim()) {
      next.displayName = displayName.trim();
    }
    if (description.trim()) {
      next.description = description.trim();
    }
    if (extraDockerArgs.trim()) {
      next.extraDockerArgs = extraDockerArgs.trim();
    }
    if (registryUsername.trim()) {
      next.registryUsername = registryUsername.trim();
    }

    const password = replacingPassword ? newPassword : runner?.registryPassword;
    if (password) {
      next.registryPassword = password;
    }
    return next;
  };

  const submit = (): void => {
    const candidate = build();
    const found = validateRunner(candidate);
    setIssues(found);
    if (found.length === 0) {
      onSave(candidate);
    }
  };

  return (
    <div className="trivy-runner-form">
      <label>
        Alias
        <input value={alias} onChange={(event) => setAlias(event.target.value)} />
      </label>
      <label>
        Image
        <input value={image} onChange={(event) => setImage(event.target.value)} />
      </label>
      <label>
        Display name
        <input value={displayName} onChange={(event) => setDisplayName(event.target.value)} />
      </label>
      <label>
        Description
        <input value={description} onChange={(event) => setDescription(event.target.value)} />
      </label>
      <label>
        Extra docker args
        <input
          value={extraDockerArgs}
          onChange={(event) => setExtraDockerArgs(event.target.value)}
        />
      </label>
      <label>
        Registry username
        <input
          value={registryUsername}
          onChange={(event) => setRegistryUsername(event.target.value)}
        />
      </label>

      {hasStoredPassword && !replacingPassword ? (
        <div>
          <span>A registry password is stored for this runner.</span>{' '}
          <button type="button" onClick={() => setReplacingPassword(true)}>
            Replace password
          </button>
        </div>
      ) : (
        <label>
          Password
          <input
            type="password"
            value={newPassword}
            onChange={(event) => setNewPassword(event.target.value)}
          />
        </label>
      )}
      <p className="trivy-warning">
        The registry password is stored in clear text in the extension settings document. Anyone
        with read access to this collection&apos;s extension data can read it.
      </p>

      <label>
        Default runner
        <input
          type="checkbox"
          checked={isDefault}
          onChange={(event) => setIsDefault(event.target.checked)}
        />
      </label>
      <label>
        Enabled
        <input
          type="checkbox"
          checked={enabled}
          onChange={(event) => setEnabled(event.target.checked)}
        />
      </label>

      <IssueList issues={issues} />

      <button type="button" onClick={submit}>
        Save
      </button>
      <button type="button" onClick={onCancel}>
        Cancel
      </button>
    </div>
  );
}
