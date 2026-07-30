import { splitArgs } from './args';
import { isSeverity, SEVERITY_ORDER } from './severity';
import { OverridableField, Scanner } from './types';

export interface ValidationIssue {
  field: string;
  message: string;
}

// The pattern anchors one leading alnum, then allows 1-30 more alnum/dash
// characters, so the accepted total length is 2-31 characters (1 + [1,30]).
const ALIAS_PATTERN = /^[a-z0-9][a-z0-9-]{1,30}$/;

// A digest reference (`@sha256:<hex>`) pins exact image content, which is
// strictly more reproducible than any tag. It is accepted regardless of
// what tag, if any, precedes the digest marker.
const DIGEST_MARKER = '@sha256:';

// A conventional Docker tag: 1-128 characters, starting with an alnum or
// underscore, the rest alnum/dot/underscore/dash. This rejects both an
// empty tag (`image:`) and trailing garbage read as part of the tag
// (`image:0.58.1 --privileged`), since neither contains only these characters.
const TAG_PATTERN = /^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$/;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Validates an alias against ALIAS_PATTERN. Shared by `RunnerConfig.alias` and
 * `DatabaseConfig.alias`, which are held to the identical shape rule: lowercase letters,
 * digits and dashes, 2 to 31 characters, starting with a letter or digit.
 */
function validateAliasField(alias: unknown, field: string): ValidationIssue[] {
  if (typeof alias !== 'string' || !ALIAS_PATTERN.test(alias)) {
    return [
      {
        field,
        message:
          'Alias must be lowercase letters, digits and dashes, 2 to 31 characters, starting with a letter or digit.',
      },
    ];
  }
  return [];
}

/**
 * Validates an image-or-database reference: required, a string, and carrying either an
 * explicit tag or an `@sha256:` digest (see DIGEST_MARKER above for why a digest is accepted
 * regardless of what tag, if any, precedes it). Shared by `RunnerConfig.image` and
 * `DatabaseConfig`'s `repository`/`javaRepository`, which are all held to the same
 * reproducibility rule; only the field name, the human-readable label used in messages, and
 * the "required" wording differ between callers.
 */
function validateReferenceField(
  value: unknown,
  field: string,
  label: string,
  requiredMessage: string,
): ValidationIssue[] {
  if (typeof value !== 'string' || value.trim().length === 0) {
    return [{ field, message: requiredMessage }];
  }

  const reference = value.trim();
  if (reference.includes(DIGEST_MARKER)) {
    // Accepted deliberately: see DIGEST_MARKER comment above.
    return [];
  }

  const tagSeparator = reference.lastIndexOf(':');
  const hasTag = tagSeparator > reference.lastIndexOf('/');
  if (!hasTag) {
    return [
      {
        field,
        message: `${label} must carry an explicit tag, for example registry.example.com/trivy:0.58.1.`,
      },
    ];
  }

  const tag = reference.slice(tagSeparator + 1);
  if (tag === 'latest') {
    return [{ field, message: 'The latest tag is not allowed because scans must be reproducible.' }];
  }
  if (!TAG_PATTERN.test(tag)) {
    return [
      {
        field,
        message: `${label} tag "${tag}" is not a valid tag; use letters, digits, dots, underscores and dashes only.`,
      },
    ];
  }
  return [];
}

/**
 * Validates an administrator-entered-once credential pair (a registry username and
 * password): one half set without the other is always a mistake, since docker login needs
 * both. Shared by `RunnerConfig.registryUsername`/`registryPassword`, `DefaultsConfig`'s
 * deprecated `dbRegistryUsername`/`dbRegistryPassword`, and `DatabaseConfig.registryUsername`/
 * `registryPassword`.
 */
function validateCredentialPair(
  username: unknown,
  password: unknown,
  usernameField: string,
  passwordField: string,
): ValidationIssue[] {
  const issues: ValidationIssue[] = [];
  if (username !== undefined && password === undefined) {
    issues.push({ field: passwordField, message: `${passwordField} is required when ${usernameField} is set.` });
  }
  if (password !== undefined && username === undefined) {
    issues.push({ field: usernameField, message: `${usernameField} is required when ${passwordField} is set.` });
  }
  return issues;
}

/**
 * Minimal stand-in for `path.posix.normalize` (resolves `.`/`..` segments and collapses
 * repeated slashes), kept dependency-free rather than importing Node's `path` module: this
 * file is shared between the Node-side task and the browser-side hub bundle, and webpack 5
 * no longer polyfills Node core modules automatically, so `import 'path'` here would break
 * `npm run build:hub` the moment any hub component imports validateDefaults.
 */
function normalizePosixPath(input: string): string {
  const absolute = input.startsWith('/');
  const resolved: string[] = [];
  for (const segment of input.split('/')) {
    if (segment === '' || segment === '.') {
      continue;
    }
    if (segment === '..') {
      if (resolved.length > 0 && resolved[resolved.length - 1] !== '..') {
        resolved.pop();
      } else if (!absolute) {
        resolved.push('..');
      }
      continue;
    }
    resolved.push(segment);
  }
  return (absolute ? '/' : '') + resolved.join('/');
}

/**
 * `satisfies Record<OverridableField, true>` makes this map exhaustive at compile
 * time in both directions, mirroring the equivalent map in
 * `src/task/ConfigResolver.ts` (duplicated rather than imported: shared/ must not
 * depend on task/). Deriving the allowed list from the type here means a future
 * `OverridableField` member cannot be silently rejected by `allowOverrides`
 * validation just because this file forgot about it.
 */
const ALL_OVERRIDABLE_FIELDS = {
  runner: true,
  severities: true,
  scanners: true,
  failOn: true,
  ignoreUnfixed: true,
  timeoutMinutes: true,
  skipDbUpdate: true,
  useDockerSocket: true,
  extraTrivyArgs: true,
  ignoreFile: true,
} satisfies Record<OverridableField, true>;

const ALL_OVERRIDABLE_FIELD_LIST = Object.keys(ALL_OVERRIDABLE_FIELDS) as OverridableField[];
const ALL_OVERRIDABLE_FIELD_SET = new Set<string>(ALL_OVERRIDABLE_FIELD_LIST);

/** Same exhaustiveness technique as ALL_OVERRIDABLE_FIELDS above, for the Scanner union. */
const ALL_SCANNERS_MAP = {
  vuln: true,
  secret: true,
  misconfig: true,
  license: true,
} satisfies Record<Scanner, true>;

const ALL_SCANNERS_LIST = Object.keys(ALL_SCANNERS_MAP) as Scanner[];
const ALL_SCANNERS_SET = new Set<string>(ALL_SCANNERS_LIST);

// FailOn permits every Severity except UNKNOWN (see the type's doc comment in
// shared/types.ts) plus the literal 'none'. Derived from SEVERITY_ORDER so this
// list cannot drift from the Severity vocabulary as it grows.
const FAIL_ON_SEVERITIES = SEVERITY_ORDER.filter((severity) => severity !== 'UNKNOWN');

/**
 * Validates a single runner. The input comes from admin-form state or from a
 * settings document read back over REST that any administrator can hand-edit,
 * so its shape cannot be trusted at compile time even though callers usually
 * have a typed `RunnerConfig` in hand.
 */
export function validateRunner(runner: unknown): ValidationIssue[] {
  if (!isRecord(runner)) {
    return [{ field: 'runner', message: 'Runner must be an object.' }];
  }

  const issues: ValidationIssue[] = [];

  issues.push(...validateAliasField(runner.alias, 'alias'));
  issues.push(...validateReferenceField(runner.image, 'image', 'Image', 'Image reference is required.'));

  // Entered once by an administrator, not per pipeline (see RunnerConfig's doc comment).
  issues.push(
    ...validateCredentialPair(runner.registryUsername, runner.registryPassword, 'registryUsername', 'registryPassword'),
  );

  const extraDockerArgs = runner.extraDockerArgs;
  if (extraDockerArgs !== undefined) {
    if (typeof extraDockerArgs !== 'string') {
      issues.push({ field: 'extraDockerArgs', message: 'extraDockerArgs must be a string.' });
    } else {
      try {
        splitArgs(extraDockerArgs);
      } catch (error) {
        issues.push({ field: 'extraDockerArgs', message: (error as Error).message });
      }
    }
  }

  return issues;
}

/**
 * Validates catalog-wide invariants only: unique aliases and exactly one
 * enabled default runner. It does not validate individual runner fields
 * (alias shape, image reference, extra docker args, ...) - call
 * `validateRunner` on each entry to catch those; the form validates one
 * runner as the admin types, this validates the document as a whole.
 */
export function validateCatalog(runners: unknown): ValidationIssue[] {
  if (!Array.isArray(runners)) {
    return [{ field: 'runners', message: 'The runner catalog must be a list of runners.' }];
  }

  const issues: ValidationIssue[] = [];
  const validRunners: Record<string, unknown>[] = [];

  runners.forEach((entry, index) => {
    if (!isRecord(entry)) {
      issues.push({
        field: `runners[${index}]`,
        message: `Runner at index ${index} must be an object.`,
      });
      return;
    }
    validRunners.push(entry);
  });

  const seen = new Set<string>();
  const duplicatesReported = new Set<string>();
  for (const runner of validRunners) {
    const alias = runner.alias;
    if (typeof alias !== 'string') {
      // A malformed alias is validateRunner's concern, not a cross-runner one.
      continue;
    }
    if (seen.has(alias)) {
      if (!duplicatesReported.has(alias)) {
        issues.push({ field: 'alias', message: `Duplicate runner alias "${alias}".` });
        duplicatesReported.add(alias);
      }
    } else {
      seen.add(alias);
    }
  }

  const defaults = validRunners.filter((runner) => runner.isDefault);
  if (defaults.length !== 1) {
    const aliasOf = (runner: Record<string, unknown>): string =>
      typeof runner.alias === 'string' ? runner.alias : String(runner.alias);
    const suffix =
      defaults.length > 0 ? `: ${defaults.map((runner) => `"${aliasOf(runner)}"`).join(', ')}` : '';
    issues.push({
      field: 'isDefault',
      message: `The catalog must contain exactly one default runner, found ${defaults.length}${suffix}.`,
    });
  } else if (defaults[0].enabled === false) {
    const alias = typeof defaults[0].alias === 'string' ? defaults[0].alias : String(defaults[0].alias);
    issues.push({
      field: 'isDefault',
      message: `Default runner "${alias}" is disabled. Enable it or mark another runner as default.`,
    });
  }

  return issues;
}

/**
 * Validates global defaults read from admin-form state or a hand-editable
 * REST document; see `validateRunner` for why the input cannot be trusted
 * to already match `DefaultsConfig` at runtime.
 */
export function validateDefaults(config: unknown): ValidationIssue[] {
  if (!isRecord(config)) {
    return [{ field: 'defaults', message: 'Defaults must be an object.' }];
  }

  const issues: ValidationIssue[] = [];

  // dbRepository (and javaDbRepository, dbRegistryUsername/Password below) are deprecated:
  // see DefaultsConfig's doc comment. A fully migrated configuration has none of them set at
  // all, so their absence is not validated here any more; the equivalent "is a database
  // actually configured" check now lives in validateDatabaseCatalogue (does the catalogue have
  // any entries?) and validateRunnerDatabaseLinks (does this runner name one?).

  if (config.timeoutMinutes !== undefined) {
    const timeout = config.timeoutMinutes;
    if (typeof timeout !== 'number' || !Number.isFinite(timeout) || timeout <= 0) {
      issues.push({ field: 'timeoutMinutes', message: 'Timeout must be a number greater than zero.' });
    }
  }

  if (config.severities !== undefined) {
    if (!Array.isArray(config.severities) || config.severities.length === 0) {
      issues.push({ field: 'severities', message: 'Select at least one severity.' });
    } else {
      config.severities.forEach((severity, index) => {
        if (typeof severity !== 'string' || !isSeverity(severity)) {
          issues.push({
            field: 'severities',
            message: `severities[${index}] "${String(severity)}" is not a valid severity. Allowed values: ${SEVERITY_ORDER.join(', ')}.`,
          });
        }
      });
    }
  }

  if (config.scanners !== undefined) {
    if (!Array.isArray(config.scanners) || config.scanners.length === 0) {
      issues.push({ field: 'scanners', message: 'Select at least one scanner.' });
    } else {
      config.scanners.forEach((scanner, index) => {
        if (typeof scanner !== 'string' || !ALL_SCANNERS_SET.has(scanner)) {
          issues.push({
            field: 'scanners',
            message: `scanners[${index}] "${String(scanner)}" is not a valid scanner. Allowed values: ${ALL_SCANNERS_LIST.join(', ')}.`,
          });
        }
      });
    }
  }

  if (config.failOn !== undefined) {
    const failOn = config.failOn;
    const isValid =
      failOn === 'none' || (typeof failOn === 'string' && (FAIL_ON_SEVERITIES as readonly string[]).includes(failOn));
    if (!isValid) {
      issues.push({
        field: 'failOn',
        message:
          `failOn "${String(failOn)}" is not valid. Allowed values: none, ${FAIL_ON_SEVERITIES.join(', ')}. ` +
          'UNKNOWN is deliberately excluded: it ranks lowest of all severities, so using it as a threshold ' +
          'would fail on every finding, the opposite of what a lowest-severity threshold suggests.',
      });
    }
  }

  if (config.allowOverrides !== undefined) {
    const allowOverrides = config.allowOverrides;
    if (!Array.isArray(allowOverrides)) {
      issues.push({
        field: 'allowOverrides',
        message: `allowOverrides must be a list of fields. Allowed values: ${ALL_OVERRIDABLE_FIELD_LIST.join(', ')}.`,
      });
    } else {
      allowOverrides.forEach((field, index) => {
        if (typeof field !== 'string' || !ALL_OVERRIDABLE_FIELD_SET.has(field)) {
          issues.push({
            field: 'allowOverrides',
            message: `allowOverrides[${index}] "${String(field)}" is not a recognized field. Allowed values: ${ALL_OVERRIDABLE_FIELD_LIST.join(', ')}.`,
          });
        }
      });
    }
  }

  // Same pairing rule as validateRunner's registryUsername/registryPassword above, for the
  // deprecated database mirror credentials (DefaultsConfig's doc comment explains both the
  // deprecation and the collision with the scanned image's credentials this pair is
  // otherwise subject to).
  issues.push(
    ...validateCredentialPair(
      config.dbRegistryUsername,
      config.dbRegistryPassword,
      'dbRegistryUsername',
      'dbRegistryPassword',
    ),
  );

  if (config.cacheDir !== undefined) {
    const cacheDir = config.cacheDir;
    if (typeof cacheDir !== 'string' || cacheDir.trim().length === 0) {
      issues.push({ field: 'cacheDir', message: 'cacheDir must be a non-empty string.' });
    } else if (!cacheDir.startsWith('/')) {
      issues.push({
        field: 'cacheDir',
        message: 'cacheDir must be an absolute path, for example /agent/_trivy-cache.',
      });
    } else {
      // DockerCommand mounts cacheDir read-write as `-v cacheDir:/root/.cache/trivy`.
      // Fewer than two path segments means the filesystem root itself
      // (0 segments) or a single top-level directory such as /etc or /var
      // (1 segment) - either would mount a directory no scan container
      // should be able to write into.
      const segments = normalizePosixPath(cacheDir).split('/').filter((segment) => segment.length > 0);
      if (segments.length < 2) {
        issues.push({
          field: 'cacheDir',
          message: `cacheDir "${cacheDir}" is the filesystem root or a bare top-level directory; mounting it read-write into the scan container is not allowed. Use a dedicated subdirectory, for example /agent/_trivy-cache.`,
        });
      }
    }
  }

  return issues;
}

/**
 * Validates a single database catalogue entry. Input comes from admin-form state or a
 * hand-editable REST document, same caveat as `validateRunner`.
 */
export function validateDatabase(database: unknown): ValidationIssue[] {
  if (!isRecord(database)) {
    return [{ field: 'database', message: 'Database must be an object.' }];
  }

  const issues: ValidationIssue[] = [];

  issues.push(...validateAliasField(database.alias, 'alias'));
  issues.push(
    ...validateReferenceField(database.repository, 'repository', 'Repository', 'Repository is required.'),
  );

  if (database.javaRepository !== undefined) {
    issues.push(
      ...validateReferenceField(
        database.javaRepository,
        'javaRepository',
        'javaRepository',
        'javaRepository must be a non-empty string when set.',
      ),
    );
  }

  // Same pairing rule as validateRunner's registryUsername/registryPassword above.
  issues.push(
    ...validateCredentialPair(
      database.registryUsername,
      database.registryPassword,
      'registryUsername',
      'registryPassword',
    ),
  );

  return issues;
}

/**
 * Validates catalogue-wide invariants only: an array of objects with unique aliases. Unlike
 * `validateCatalog` for runners, there is no "default database" concept to check -- a runner
 * names one explicitly (`RunnerConfig.database`) or falls back to `DefaultsConfig`'s
 * deprecated fields; call `validateDatabase` on each entry to catch per-entry issues (alias
 * shape, repository reference, credential pairing, ...), which this function does not.
 */
export function validateDatabaseCatalogue(databases: unknown): ValidationIssue[] {
  if (!Array.isArray(databases)) {
    return [{ field: 'databases', message: 'The database catalogue must be a list of databases.' }];
  }

  const issues: ValidationIssue[] = [];
  const validDatabases: Record<string, unknown>[] = [];

  databases.forEach((entry, index) => {
    if (!isRecord(entry)) {
      issues.push({
        field: `databases[${index}]`,
        message: `Database at index ${index} must be an object.`,
      });
      return;
    }
    validDatabases.push(entry);
  });

  const seen = new Set<string>();
  const duplicatesReported = new Set<string>();
  for (const database of validDatabases) {
    const alias = database.alias;
    if (typeof alias !== 'string') {
      // A malformed alias is validateDatabase's concern, not a cross-entry one.
      continue;
    }
    if (seen.has(alias)) {
      if (!duplicatesReported.has(alias)) {
        issues.push({ field: 'alias', message: `Duplicate database alias "${alias}".` });
        duplicatesReported.add(alias);
      }
    } else {
      seen.add(alias);
    }
  }

  return issues;
}

/**
 * Validates that every runner naming a `database` alias names one that actually exists in the
 * catalogue. A runner with `database` omitted is not an issue here -- it falls back to
 * `DefaultsConfig`'s deprecated fields, see `RunnerConfig.database`'s doc comment -- but a
 * runner naming an empty string is a mistake, not an omission, and is reported. Mirrors the
 * "runner not found" message shape used for `TaskInputs.runner` resolution
 * (`ConfigResolver.selectRunner`): name what was requested, then list what does exist.
 */
export function validateRunnerDatabaseLinks(runners: unknown, databases: unknown): ValidationIssue[] {
  if (!Array.isArray(runners)) {
    return [{ field: 'runners', message: 'The runner catalog must be a list of runners.' }];
  }
  if (!Array.isArray(databases)) {
    return [{ field: 'databases', message: 'The database catalogue must be a list of databases.' }];
  }

  const knownAliases: string[] = [];
  const knownAliasSet = new Set<string>();
  databases.forEach((entry) => {
    if (isRecord(entry) && typeof entry.alias === 'string' && !knownAliasSet.has(entry.alias)) {
      knownAliasSet.add(entry.alias);
      knownAliases.push(entry.alias);
    }
  });

  const issues: ValidationIssue[] = [];

  runners.forEach((entry, index) => {
    if (!isRecord(entry)) {
      // Not this function's concern: validateCatalog/validateRunner report shape issues.
      return;
    }

    const database = entry.database;
    if (database === undefined) {
      // Falls back to DefaultsConfig's deprecated fields; see RunnerConfig.database's doc comment.
      return;
    }

    if (database === '') {
      issues.push({
        field: `runners[${index}].database`,
        message:
          `runners[${index}].database is an empty string, which is not a valid alias. ` +
          'Omit the field to fall back to the deprecated defaults fields instead, or name a database alias.',
      });
      return;
    }

    if (typeof database !== 'string' || !knownAliasSet.has(database)) {
      if (knownAliases.length === 0) {
        issues.push({
          field: `runners[${index}].database`,
          message: `Database "${String(database)}" does not exist, and no databases are currently configured.`,
        });
      } else {
        issues.push({
          field: `runners[${index}].database`,
          message: `Database "${String(database)}" does not exist. Known databases: ${knownAliases.join(', ')}.`,
        });
      }
    }
  });

  return issues;
}
