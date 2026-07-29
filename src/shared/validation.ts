import { splitArgs } from './args';
import { DefaultsConfig, RunnerConfig } from './types';

export interface ValidationIssue {
  field: string;
  message: string;
}

const ALIAS_PATTERN = /^[a-z0-9][a-z0-9-]{1,30}$/;

export function validateRunner(runner: RunnerConfig): ValidationIssue[] {
  const issues: ValidationIssue[] = [];

  if (!ALIAS_PATTERN.test(runner.alias ?? '')) {
    issues.push({
      field: 'alias',
      message:
        'Alias must be lowercase letters, digits and dashes, 2 to 31 characters, starting with a letter or digit.',
    });
  }

  const image = (runner.image ?? '').trim();
  if (image.length === 0) {
    issues.push({ field: 'image', message: 'Image reference is required.' });
  } else {
    const tagSeparator = image.lastIndexOf(':');
    const hasTag = tagSeparator > image.lastIndexOf('/');
    if (!hasTag) {
      issues.push({
        field: 'image',
        message: 'Image must carry an explicit tag, for example reg.corp/trivy:0.58.1.',
      });
    } else if (image.slice(tagSeparator + 1) === 'latest') {
      issues.push({
        field: 'image',
        message: 'The latest tag is not allowed because scans must be reproducible.',
      });
    }
  }

  if (runner.extraDockerArgs) {
    try {
      splitArgs(runner.extraDockerArgs);
    } catch (error) {
      issues.push({ field: 'extraDockerArgs', message: (error as Error).message });
    }
  }

  return issues;
}

export function validateCatalog(runners: RunnerConfig[]): ValidationIssue[] {
  const issues: ValidationIssue[] = [];

  const seen = new Set<string>();
  for (const runner of runners) {
    if (seen.has(runner.alias)) {
      issues.push({ field: 'alias', message: `Duplicate runner alias "${runner.alias}".` });
    }
    seen.add(runner.alias);
  }

  const defaults = runners.filter((runner) => runner.isDefault);
  if (defaults.length !== 1) {
    issues.push({
      field: 'isDefault',
      message: `The catalog must contain exactly one default runner, found ${defaults.length}.`,
    });
  } else if (defaults[0].enabled === false) {
    issues.push({
      field: 'isDefault',
      message: `Default runner "${defaults[0].alias}" is disabled. Enable it or mark another runner as default.`,
    });
  }

  return issues;
}

export function validateDefaults(config: DefaultsConfig): ValidationIssue[] {
  const issues: ValidationIssue[] = [];

  if ((config.dbRepository ?? '').trim().length === 0) {
    issues.push({
      field: 'dbRepository',
      message: 'A vulnerability database repository is required: build agents have no internet access.',
    });
  }

  if (config.timeoutMinutes !== undefined && config.timeoutMinutes <= 0) {
    issues.push({ field: 'timeoutMinutes', message: 'Timeout must be greater than zero.' });
  }

  if (config.severities !== undefined && config.severities.length === 0) {
    issues.push({ field: 'severities', message: 'Select at least one severity.' });
  }

  if (config.scanners !== undefined && config.scanners.length === 0) {
    issues.push({ field: 'scanners', message: 'Select at least one scanner.' });
  }

  return issues;
}
