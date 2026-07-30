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

  return (
    <div className="trivy-database-form">
      <label>
        Alias
        <input value={alias} onChange={(event) => setAlias(event.target.value)} />
      </label>
      <label>
        Repository
        <input value={repository} onChange={(event) => setRepository(event.target.value)} />
      </label>
      <label>
        Java repository
        <input value={javaRepository} onChange={(event) => setJavaRepository(event.target.value)} />
      </label>
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
      />

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
