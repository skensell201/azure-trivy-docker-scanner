import * as React from 'react';
import { DatabaseConfig } from '../../shared/types';
import { validateDatabase, ValidationIssue } from '../../shared/validation';
import { IssueList } from './IssueList';
import { RegistryCredentialFields, useStoredPassword } from './RegistryCredentialFields';

export interface DatabaseFormProps {
  /** Undefined when adding; the existing database when editing. */
  database: DatabaseConfig | undefined;
  onSave: (database: DatabaseConfig) => void;
  onCancel: () => void;
}

export function DatabaseForm({ database, onSave, onCancel }: DatabaseFormProps): JSX.Element {
  const [alias, setAlias] = React.useState(database?.alias ?? '');
  const [repository, setRepository] = React.useState(database?.repository ?? '');
  const [javaRepository, setJavaRepository] = React.useState(database?.javaRepository ?? '');
  const [displayName, setDisplayName] = React.useState(database?.displayName ?? '');
  const [description, setDescription] = React.useState(database?.description ?? '');
  const [registryUsername, setRegistryUsername] = React.useState(database?.registryUsername ?? '');
  const [issues, setIssues] = React.useState<ValidationIssue[]>([]);

  // Same treatment as RunnerForm's registryPassword, for the same reason (see
  // RegistryCredentialFields' doc comment): never rendered, carried through untouched unless
  // explicitly replaced.
  const {
    hasStoredPassword,
    replacingPassword,
    setReplacingPassword,
    newPassword,
    setNewPassword,
    resolvedPassword,
  } = useStoredPassword(database?.registryPassword);

  const build = (): DatabaseConfig => {
    const next: DatabaseConfig = { alias: alias.trim(), repository: repository.trim() };
    if (javaRepository.trim()) {
      next.javaRepository = javaRepository.trim();
    }
    if (displayName.trim()) {
      next.displayName = displayName.trim();
    }
    if (description.trim()) {
      next.description = description.trim();
    }
    if (registryUsername.trim()) {
      next.registryUsername = registryUsername.trim();
    }
    if (resolvedPassword) {
      next.registryPassword = resolvedPassword;
    }
    return next;
  };

  const submit = (): void => {
    const candidate = build();
    const found = validateDatabase(candidate);
    setIssues(found);
    if (found.length === 0) {
      onSave(candidate);
    }
  };

  // Same convention as RunnerForm: every field validateDatabase can name gets its own spot next
  // to the input, and `otherIssues` is a safety net for anything that is not attributable to a
  // single field (none today).
  const knownFields = ['alias', 'repository', 'javaRepository', 'registryUsername', 'registryPassword'];
  const errorFor = (field: string): string | undefined =>
    issues.find((issue) => issue.field === field)?.message;
  const otherIssues = issues.filter((issue) => !knownFields.includes(issue.field));

  return (
    <div className="trivy-database-form">
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
          Repository
          <input
            className="trivy-mono"
            value={repository}
            onChange={(event) => setRepository(event.target.value)}
          />
        </label>
        {errorFor('repository') ? (
          <p role="alert" className="trivy-field-error">
            {errorFor('repository')}
          </p>
        ) : null}
      </div>
      <div className="trivy-field">
        <label>
          Java repository
          <input
            className="trivy-mono"
            value={javaRepository}
            onChange={(event) => setJavaRepository(event.target.value)}
          />
        </label>
        {errorFor('javaRepository') ? (
          <p role="alert" className="trivy-field-error">
            {errorFor('javaRepository')}
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

      <RegistryCredentialFields
        usernameLabel="Registry username"
        username={registryUsername}
        onUsernameChange={setRegistryUsername}
        passwordLabel="Password"
        storedPasswordMessage="A registry password is stored for this database."
        hasStoredPassword={hasStoredPassword}
        replacingPassword={replacingPassword}
        onReplacePassword={() => setReplacingPassword(true)}
        newPassword={newPassword}
        onNewPasswordChange={setNewPassword}
        warningText="The registry password is stored in clear text in the extension settings document. Anyone with read access to this collection's extension data can read it."
        usernameError={errorFor('registryUsername')}
        passwordError={errorFor('registryPassword')}
      />

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
