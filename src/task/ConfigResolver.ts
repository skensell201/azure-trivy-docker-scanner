import * as path from 'path';
import {
  AgentContext,
  DefaultsConfig,
  OverridableField,
  ResolvedScanConfig,
  RunnerConfig,
  TaskInputs,
} from '../shared/types';

export class PolicyViolationError extends Error {}
export class RunnerNotFoundError extends Error {}

/**
 * `satisfies Record<OverridableField, true>` makes this map exhaustive at
 * compile time in both directions: adding a member to `OverridableField`
 * without adding it here is a missing-property error, and adding a key here
 * that is not in the union is an excess-property error. That keeps the
 * documented "allowOverrides omitted means everything is overridable" case
 * honest as the union grows.
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

const ALL_OVERRIDABLE: OverridableField[] = Object.keys(ALL_OVERRIDABLE_FIELDS) as OverridableField[];

export interface ResolveArgs {
  defaults: DefaultsConfig;
  runners: RunnerConfig[];
  inputs: TaskInputs;
  agent: AgentContext;
  scanIndex: number;
}

interface PolicyViolation {
  field: OverridableField;
  /** The value that is used instead of the pipeline's, formatted for a build log. */
  enforcedValue: unknown;
}

export function resolveConfig(args: ResolveArgs): ResolvedScanConfig {
  const { defaults, runners, inputs, agent, scanIndex } = args;
  const allowed = defaults.allowOverrides ?? ALL_OVERRIDABLE;
  const violations: PolicyViolation[] = [];

  /**
   * Reads `inputs[field]` directly instead of taking the value as a separate
   * parameter, so the field being gated and the value being checked can never
   * drift apart at a call site (e.g. `pick('severities', inputs.failOn, ...)`
   * would previously compile clean and silently gate the wrong field).
   *
   * A violation does not throw immediately: it is recorded so every
   * violation in one call can be reported together (see the throw at the
   * bottom of `resolveConfig`), and the fallback is returned so the rest of
   * resolution can proceed and still produce a value for every field.
   */
  function pick<F extends OverridableField & keyof TaskInputs, D>(
    field: F,
    fallback: D,
  ): NonNullable<TaskInputs[F]> | D {
    const fromInputs = inputs[field];
    if (fromInputs === undefined) {
      return fallback;
    }
    if (!allowed.includes(field)) {
      violations.push({ field, enforcedValue: fallback });
      return fallback;
    }
    return fromInputs as NonNullable<TaskInputs[F]>;
  }

  // The runner is resolved outside `pick` because, when the override is
  // rejected, the enforced value to report is not a static fallback but
  // whichever runner the catalog resolves to by default - which requires
  // running catalog lookup first.
  const requestedRunnerAlias = normalizeRunnerAlias(inputs.runner);
  const runnerOverrideAllowed = allowed.includes('runner');
  const runner = selectRunner(runners, runnerOverrideAllowed ? requestedRunnerAlias : undefined);
  if (requestedRunnerAlias !== undefined && !runnerOverrideAllowed) {
    violations.push({ field: 'runner', enforcedValue: runner.alias });
  }

  const config: ResolvedScanConfig = {
    runner,
    scanType: inputs.scanType,
    target: inputs.target,
    severities: pick('severities', defaults.severities ?? ['CRITICAL', 'HIGH']),
    scanners: pick('scanners', defaults.scanners ?? ['vuln', 'secret']),
    failOn: pick('failOn', defaults.failOn ?? 'CRITICAL'),
    ignoreUnfixed: pick('ignoreUnfixed', defaults.ignoreUnfixed ?? false),
    skipDbUpdate: pick('skipDbUpdate', defaults.skipDbUpdate ?? false),
    timeoutMinutes: pick('timeoutMinutes', defaults.timeoutMinutes ?? 10),
    dbRepository: defaults.dbRepository,
    javaDbRepository: defaults.javaDbRepository,
    cacheDir: defaults.cacheDir ?? path.posix.join(agent.agentHomeDir, '_trivy-cache'),
    sourcesDir: agent.sourcesDir,
    workingDirectory: inputs.workingDirectory,
    // The admin has no separate default value to set for these three: they
    // can only be locked on (built-in default) or left to the pipeline.
    ignoreFile: pick('ignoreFile', undefined),
    useDockerSocket: pick('useDockerSocket', false),
    formats: inputs.formats ?? ['table', 'json'],
    generateSbom: inputs.generateSbom ?? 'off',
    publishArtifact: inputs.publishArtifact ?? true,
    // Deliberately off by default (see TaskInputs.publishTestResults and the README section on
    // publishing test results): turning it on makes every finding a *failed* JUnit test case, so
    // a pipeline whose gate passes would suddenly show failing tests in the Tests tab. Not gated
    // by allowOverrides -- see that field's own doc comment for why -- so, like publishArtifact,
    // it is read straight from the pipeline input with no admin default to fall back to.
    publishTestResults: inputs.publishTestResults ?? false,
    extraTrivyArgs: pick('extraTrivyArgs', undefined),
    buildId: agent.buildId,
    scanIndex,
    // Not gated by allowOverrides -- see the doc comment on TaskInputs.sourceTransfer:
    // this describes the agent's own topology, not a security policy, so (like
    // `formats` and `workingDirectory` above) any pipeline may always set it directly.
    sourceTransfer: inputs.sourceTransfer ?? 'mount',
  };

  if (violations.length > 0) {
    throw new PolicyViolationError(buildPolicyMessage(violations, allowed));
  }

  return config;
}

function buildPolicyMessage(violations: PolicyViolation[], allowed: OverridableField[]): string {
  const fieldList = violations.map((violation) => `"${violation.field}"`).join(' and ');
  const pronoun = violations.length > 1 ? 'them' : 'it';
  const enforcedSentences = violations
    .map((violation) => `The collection sets ${violation.field} to ${formatEnforcedValue(violation.enforcedValue)}.`)
    .join(' ');
  return (
    `The pipeline sets ${fieldList}, but the collection policy does not allow overriding ${pronoun}. ` +
    `${enforcedSentences} ` +
    `Overridable fields: ${allowed.join(', ') || 'none'}. Change the value in Collection Settings > Trivy Scanner.`
  );
}

function formatEnforcedValue(value: unknown): string {
  if (value === undefined) {
    return '(unset)';
  }
  if (Array.isArray(value)) {
    return `"${value.join(', ')}"`;
  }
  return `"${String(value)}"`;
}

/** An empty string is the same as not naming a runner at all, not a request for one named "". */
function normalizeRunnerAlias(alias: string | undefined): string | undefined {
  return alias === '' ? undefined : alias;
}

function selectRunner(runners: RunnerConfig[], requested: string | undefined): RunnerConfig {
  if (runners.length === 0) {
    throw new RunnerNotFoundError(
      'The collection has no runners configured. Add one in Collection Settings > Trivy Scanner > Runners.',
    );
  }

  const enabled = runners.filter((runner) => runner.enabled !== false);

  if (requested !== undefined) {
    const match = runners.find((runner) => runner.alias === requested);
    if (!match) {
      if (enabled.length === 0) {
        throw new RunnerNotFoundError(`Runner "${requested}" does not exist, and no runners are currently enabled.`);
      }
      throw new RunnerNotFoundError(
        `Runner "${requested}" does not exist. Enabled runners: ${enabled
          .map((runner) => runner.alias)
          .join(', ')}.`,
      );
    }
    if (match.enabled === false) {
      throw new RunnerNotFoundError(
        `Runner "${requested}" is disabled. Enable it in Collection Settings > Trivy Scanner > Runners, or choose a different runner.`,
      );
    }
    return match;
  }

  const defaultRunner = runners.find((runner) => runner.isDefault);
  if (!defaultRunner) {
    throw new RunnerNotFoundError(
      'No default runner is configured. Mark one runner as default in Collection Settings > Trivy Scanner > Runners, or set the "runner" input.',
    );
  }
  if (defaultRunner.enabled === false) {
    // Wording matches `validateCatalog` in shared/validation.ts so the two error paths do not drift.
    throw new RunnerNotFoundError(
      `Default runner "${defaultRunner.alias}" is disabled. Enable it or mark another runner as default.`,
    );
  }
  return defaultRunner;
}
