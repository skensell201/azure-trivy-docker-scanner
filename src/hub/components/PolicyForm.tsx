import * as React from 'react';
import { DefaultsConfig, OverridableField } from '../../shared/types';

/**
 * `satisfies Record<OverridableField, string>` makes this map exhaustive at
 * compile time: adding a member to `OverridableField` without adding it here
 * is a missing-property error, so a new overridable field cannot silently
 * drop out of this checkbox list the way it could if the list were
 * maintained by hand.
 */
const OVERRIDABLE_FIELD_LABELS = {
  runner: 'Which runner the pipeline uses.',
  severities: 'Which severities are reported.',
  scanners: 'Which scanners run (vuln, secret, misconfig, license).',
  failOn: 'The severity threshold that fails the build.',
  ignoreUnfixed: 'Whether findings with no fix available are ignored.',
  timeoutMinutes: 'How long the scan may run before timing out.',
  skipDbUpdate: 'Whether the vulnerability database update is skipped.',
  useDockerSocket: 'Whether the pipeline may bind-mount the Docker socket.',
  extraTrivyArgs: 'Extra raw command-line arguments passed to trivy.',
  ignoreFile: 'Which .trivyignore file is used to suppress findings.',
} satisfies Record<OverridableField, string>;

const ALL_OVERRIDABLE_FIELDS = Object.keys(OVERRIDABLE_FIELD_LABELS) as OverridableField[];

export interface PolicyFormProps {
  defaults: DefaultsConfig;
  onSave: (defaults: DefaultsConfig) => void;
}

export function PolicyForm({ defaults, onSave }: PolicyFormProps): JSX.Element {
  // Absent `allowOverrides` means every field may be overridden; an empty array means none may
  // be. Both are legitimate stored states, and they mean opposite things, so the initial checkbox
  // state has to distinguish "field is missing" from "field is an empty array" rather than
  // defaulting a missing array to `[]`.
  const [allowed, setAllowed] = React.useState<Set<OverridableField>>(
    () => new Set(defaults.allowOverrides ?? ALL_OVERRIDABLE_FIELDS),
  );

  const toggle = (field: OverridableField): void => {
    setAllowed((previous) => {
      const next = new Set(previous);
      if (next.has(field)) {
        next.delete(field);
      } else {
        next.add(field);
      }
      return next;
    });
  };

  const submit = (): void => {
    // Always save an explicit array, even when every box is checked: relying on omitting the
    // key to mean "everything allowed" would silently flip meaning the moment an administrator
    // unchecked everything and then rechecked it, since the resulting array would be
    // indistinguishable from having started empty.
    const allowOverrides = ALL_OVERRIDABLE_FIELDS.filter((field) => allowed.has(field));
    onSave({ ...defaults, allowOverrides });
  };

  return (
    <div className="trivy-policy-form">
      <p>
        Absent means every field may be overridden by a pipeline; an empty list means none may
        be. These two states mean opposite things, so unchecking every box and saving still
        stores an explicit empty list, not the absence of the setting.
      </p>
      <p className="trivy-warning">
        Leaving <strong>extraTrivyArgs</strong>, <strong>ignoreFile</strong>, or{' '}
        <strong>useDockerSocket</strong> open lets a pipeline defeat the other locks: passing{' '}
        <code>--severity LOW</code> in extra arguments overrides a locked severity list, and a
        checked-in <code>.trivyignore</code> file mutes findings and so defeats the failure
        threshold.
      </p>
      {ALL_OVERRIDABLE_FIELDS.map((field) => (
        <label key={field}>
          <input
            type="checkbox"
            checked={allowed.has(field)}
            onChange={() => toggle(field)}
          />
          {field}
          <span> — {OVERRIDABLE_FIELD_LABELS[field]}</span>
        </label>
      ))}
      <button type="button" onClick={submit}>
        Save
      </button>
    </div>
  );
}
