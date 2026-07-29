import { splitArgs } from './args';

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
    }
  }

  if (config.scanners !== undefined) {
    if (!Array.isArray(config.scanners) || config.scanners.length === 0) {
      issues.push({ field: 'scanners', message: 'Select at least one scanner.' });
    }
  }

  return issues;
}
