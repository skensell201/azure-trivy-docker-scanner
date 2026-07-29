import * as path from 'path';
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

  const alias = runner.alias;
  if (typeof alias !== 'string' || !ALIAS_PATTERN.test(alias)) {
    issues.push({
      field: 'alias',
      message:
        'Alias must be lowercase letters, digits and dashes, 2 to 31 characters, starting with a letter or digit.',
    });
  }

  const imageRaw = runner.image;
  if (typeof imageRaw !== 'string' || imageRaw.trim().length === 0) {
    issues.push({ field: 'image', message: 'Image reference is required.' });
  } else {
    const image = imageRaw.trim();
    if (image.includes(DIGEST_MARKER)) {
      // Accepted deliberately: see DIGEST_MARKER comment above.
    } else {
      const tagSeparator = image.lastIndexOf(':');
      const hasTag = tagSeparator > image.lastIndexOf('/');
      if (!hasTag) {
        issues.push({
          field: 'image',
          message: 'Image must carry an explicit tag, for example reg.corp/trivy:0.58.1.',
        });
      } else {
        const tag = image.slice(tagSeparator + 1);
        if (tag === 'latest') {
          issues.push({
            field: 'image',
            message: 'The latest tag is not allowed because scans must be reproducible.',
          });
        } else if (!TAG_PATTERN.test(tag)) {
          issues.push({
            field: 'image',
            message: `Image tag "${tag}" is not a valid tag; use letters, digits, dots, underscores and dashes only.`,
          });
        }
      }
    }
  }

  // Entered once by an administrator, not per pipeline (see RunnerConfig's doc comment):
  // one half without the other is always a mistake, since docker login needs both.
  const registryUsername = runner.registryUsername;
  const registryPassword = runner.registryPassword;
  if (registryUsername !== undefined && registryPassword === undefined) {
    issues.push({
      field: 'registryPassword',
      message: 'registryPassword is required when registryUsername is set.',
    });
  }
  if (registryPassword !== undefined && registryUsername === undefined) {
    issues.push({
      field: 'registryUsername',
      message: 'registryUsername is required when registryPassword is set.',
    });
  }

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

  const dbRepository = config.dbRepository;
  if (typeof dbRepository !== 'string' || dbRepository.trim().length === 0) {
    issues.push({
      field: 'dbRepository',
      message: 'A vulnerability database repository is required: build agents have no internet access.',
    });
  }

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
  // database mirror's own credentials (DefaultsConfig's doc comment explains the collision
  // with the scanned image's credentials that this pair is otherwise subject to).
  const dbRegistryUsername = config.dbRegistryUsername;
  const dbRegistryPassword = config.dbRegistryPassword;
  if (dbRegistryUsername !== undefined && dbRegistryPassword === undefined) {
    issues.push({
      field: 'dbRegistryPassword',
      message: 'dbRegistryPassword is required when dbRegistryUsername is set.',
    });
  }
  if (dbRegistryPassword !== undefined && dbRegistryUsername === undefined) {
    issues.push({
      field: 'dbRegistryUsername',
      message: 'dbRegistryUsername is required when dbRegistryPassword is set.',
    });
  }

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
      const segments = path.posix.normalize(cacheDir).split('/').filter((segment) => segment.length > 0);
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
