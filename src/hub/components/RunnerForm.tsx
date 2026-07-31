import * as React from 'react';
import { DatabaseConfig, RunnerConfig } from '../../shared/types';
import { validateRunner, ValidationIssue } from '../../shared/validation';
import { IssueList } from './IssueList';
import { RegistryCredentialFields, useStoredPassword } from './RegistryCredentialFields';

export interface RunnerFormProps {
  /** Undefined when adding; the existing runner when editing. */
  runner: RunnerConfig | undefined;
  /**
   * The full database catalogue, so the runner's database is a select populated from what
   * actually exists rather than a free-text field an administrator could mistype. This form
   * does not fetch it - the catalogue is App's to load, this form's only to render.
   */
  databases: DatabaseConfig[];
  onSave: (runner: RunnerConfig) => void;
  onCancel: () => void;
}

export function RunnerForm({ runner, databases, onSave, onCancel }: RunnerFormProps): JSX.Element {
  const [alias, setAlias] = React.useState(runner?.alias ?? '');
  const [image, setImage] = React.useState(runner?.image ?? '');
  const [displayName, setDisplayName] = React.useState(runner?.displayName ?? '');
  const [description, setDescription] = React.useState(runner?.description ?? '');
  const [extraDockerArgs, setExtraDockerArgs] = React.useState(runner?.extraDockerArgs ?? '');
  const [registryUsername, setRegistryUsername] = React.useState(runner?.registryUsername ?? '');
  const [database, setDatabase] = React.useState(runner?.database ?? '');
  const [isDefault, setIsDefault] = React.useState(runner?.isDefault ?? false);
  const [enabled, setEnabled] = React.useState(runner?.enabled !== false);
  const [issues, setIssues] = React.useState<ValidationIssue[]>([]);

  // The stored password is never rendered. It is only carried through untouched unless the
  // administrator explicitly chooses to replace it, so saving a form nobody edited cannot
  // wipe the credential out of the settings document.
  const {
    hasStoredPassword,
    replacingPassword,
    setReplacingPassword,
    newPassword,
    setNewPassword,
    resolvedPassword,
  } = useStoredPassword(runner?.registryPassword);

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
    if (database) {
      next.database = database;
    }

    if (resolvedPassword) {
      next.registryPassword = resolvedPassword;
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

  // `validateRunner` names every issue it can produce by one of these fields, so each has a
  // dedicated spot in the pane, right next to the input it concerns, phrased as the fix rather
  // than the rule (see the field's own message text in shared/validation.ts). `knownFields`
  // exists only so `otherIssues` below can catch anything that is not attributable to a single
  // field - there is none today, but a future validateRunner field the pane forgot to wire up
  // fails safely into the fallback list instead of silently vanishing.
  const knownFields = ['alias', 'image', 'registryUsername', 'registryPassword', 'extraDockerArgs'];
  const errorFor = (field: string): string | undefined =>
    issues.find((issue) => issue.field === field)?.message;
  const otherIssues = issues.filter((issue) => !knownFields.includes(issue.field));

  return (
    <div className="trivy-runner-form">
      <div className="trivy-field">
        <label>
          Alias
          <input className="trivy-mono" value={alias} onChange={(event) => setAlias(event.target.value)} />
        </label>
        {errorFor('alias') ? (
          <p role="alert" className="trivy-field-error">
            {errorFor('alias')}
          </p>
        ) : null}
      </div>
      <div className="trivy-field">
        <label>
          Image
          <input className="trivy-mono" value={image} onChange={(event) => setImage(event.target.value)} />
        </label>
        {errorFor('image') ? (
          <p role="alert" className="trivy-field-error">
            {errorFor('image')}
          </p>
        ) : null}
      </div>
      <label>
        Display name
        <input value={displayName} onChange={(event) => setDisplayName(event.target.value)} />
      </label>
      <label>
        Description
        <input value={description} onChange={(event) => setDescription(event.target.value)} />
      </label>
      <div className="trivy-field">
        <label>
          Extra docker args
          <input
            value={extraDockerArgs}
            onChange={(event) => setExtraDockerArgs(event.target.value)}
          />
        </label>
        {errorFor('extraDockerArgs') ? (
          <p role="alert" className="trivy-field-error">
            {errorFor('extraDockerArgs')}
          </p>
        ) : null}
      </div>
      <label>
        Database
        <select value={database} onChange={(event) => setDatabase(event.target.value)}>
          <option value="">
            Not linked - uses the deprecated Defaults tab settings (being phased out)
          </option>
          {databases.map((entry) => (
            <option key={entry.alias} value={entry.alias}>
              {entry.alias}
            </option>
          ))}
        </select>
      </label>

      <RegistryCredentialFields
        usernameLabel="Registry username"
        username={registryUsername}
        onUsernameChange={setRegistryUsername}
        passwordLabel="Password"
        storedPasswordMessage="A registry password is stored for this runner."
        hasStoredPassword={hasStoredPassword}
        replacingPassword={replacingPassword}
        onReplacePassword={() => setReplacingPassword(true)}
        newPassword={newPassword}
        onNewPasswordChange={setNewPassword}
        warningText="The registry password is stored in clear text in the extension settings document. Anyone with read access to this collection's extension data can read it."
        usernameError={errorFor('registryUsername')}
        passwordError={errorFor('registryPassword')}
      />

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

      <IssueList issues={otherIssues} />

      <button type="button" onClick={submit}>
        Save
      </button>
      <button type="button" onClick={onCancel}>
        Cancel
      </button>
    </div>
  );
}
