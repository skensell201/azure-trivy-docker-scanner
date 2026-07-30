import * as React from 'react';

/**
 * State for an administrator-entered-once registry password: never rendered once stored, and
 * carried through untouched unless the administrator explicitly chooses to replace it, so saving
 * a form nobody edited cannot wipe the credential out of the settings document. Shared by
 * `RunnerForm` and `DatabaseForm`, which both hold a `registryPassword` under this exact rule
 * (see `RunnerConfig.registryPassword`/`DatabaseConfig.registryPassword` in shared/types.ts).
 */
export function useStoredPassword(storedPassword: string | undefined) {
  const hasStoredPassword = Boolean(storedPassword);
  const [replacingPassword, setReplacingPassword] = React.useState(!hasStoredPassword);
  const [newPassword, setNewPassword] = React.useState('');

  /** What to save: the freshly typed password while replacing, otherwise whatever was stored. */
  const resolvedPassword = replacingPassword ? newPassword : storedPassword;

  return { hasStoredPassword, replacingPassword, setReplacingPassword, newPassword, setNewPassword, resolvedPassword };
}

export interface RegistryCredentialFieldsProps {
  usernameLabel: string;
  username: string;
  onUsernameChange: (value: string) => void;
  passwordLabel: string;
  /** e.g. "A registry password is stored for this runner." - names what the password belongs to. */
  storedPasswordMessage: string;
  hasStoredPassword: boolean;
  replacingPassword: boolean;
  onReplacePassword: () => void;
  newPassword: string;
  onNewPasswordChange: (value: string) => void;
  /** e.g. "The registry password is stored in clear text..." - names what the password belongs to. */
  warningText: string;
}

/**
 * The registry username input plus the stored/replace/new password UI, identical between
 * `RunnerForm` and `DatabaseForm` down to the clear-text-storage warning: both forms hold an
 * administrator-entered-once credential pair under the same plain-text-storage caveat (see
 * `useStoredPassword` above). Only the labels and messages differ between callers.
 */
export function RegistryCredentialFields({
  usernameLabel,
  username,
  onUsernameChange,
  passwordLabel,
  storedPasswordMessage,
  hasStoredPassword,
  replacingPassword,
  onReplacePassword,
  newPassword,
  onNewPasswordChange,
  warningText,
}: RegistryCredentialFieldsProps): JSX.Element {
  return (
    <>
      <label>
        {usernameLabel}
        <input value={username} onChange={(event) => onUsernameChange(event.target.value)} />
      </label>

      {hasStoredPassword && !replacingPassword ? (
        <div>
          <span>{storedPasswordMessage}</span>{' '}
          <button type="button" onClick={onReplacePassword}>
            Replace password
          </button>
        </div>
      ) : (
        <label>
          {passwordLabel}
          <input
            type="password"
            value={newPassword}
            onChange={(event) => onNewPasswordChange(event.target.value)}
          />
        </label>
      )}
      <p className="trivy-warning">{warningText}</p>
    </>
  );
}
