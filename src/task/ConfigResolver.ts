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

const ALL_OVERRIDABLE: OverridableField[] = [
  'runner',
  'severities',
  'scanners',
  'failOn',
  'ignoreUnfixed',
  'timeoutMinutes',
  'skipDbUpdate',
];

export interface ResolveArgs {
  defaults: DefaultsConfig;
  runners: RunnerConfig[];
  inputs: TaskInputs;
  agent: AgentContext;
  scanIndex: number;
}

export function resolveConfig(args: ResolveArgs): ResolvedScanConfig {
  const { defaults, runners, inputs, agent, scanIndex } = args;
  const allowed = defaults.allowOverrides ?? ALL_OVERRIDABLE;

  const pick = <T>(field: OverridableField, fromInputs: T | undefined, fallback: T): T => {
    if (fromInputs === undefined) {
      return fallback;
    }
    if (!allowed.includes(field)) {
      throw new PolicyViolationError(
        `The pipeline sets "${field}", but the project policy does not allow overriding it. ` +
          `Overridable fields: ${allowed.join(', ') || 'none'}. Change the value in Project Settings > Trivy Scanner.`,
      );
    }
    return fromInputs;
  };

  const runner = selectRunner(runners, pick('runner', inputs.runner, undefined));

  return {
    runner,
    scanType: inputs.scanType,
    target: inputs.target,
    severities: pick('severities', inputs.severities, defaults.severities ?? ['CRITICAL', 'HIGH']),
    scanners: pick('scanners', inputs.scanners, defaults.scanners ?? ['vuln', 'secret']),
    failOn: pick('failOn', inputs.failOn, defaults.failOn ?? 'CRITICAL'),
    ignoreUnfixed: pick('ignoreUnfixed', inputs.ignoreUnfixed, defaults.ignoreUnfixed ?? false),
    skipDbUpdate: pick('skipDbUpdate', inputs.skipDbUpdate, defaults.skipDbUpdate ?? false),
    timeoutMinutes: pick('timeoutMinutes', inputs.timeoutMinutes, defaults.timeoutMinutes ?? 10),
    dbRepository: defaults.dbRepository,
    javaDbRepository: defaults.javaDbRepository,
    cacheDir: defaults.cacheDir ?? path.posix.join(agent.agentHomeDir, '_trivy-cache'),
    sourcesDir: agent.sourcesDir,
    workingDirectory: inputs.workingDirectory,
    ignoreFile: inputs.ignoreFile,
    useDockerSocket: inputs.useDockerSocket ?? false,
    formats: inputs.formats ?? ['table', 'json'],
    generateSbom: inputs.generateSbom ?? 'off',
    publishArtifact: inputs.publishArtifact ?? true,
    extraTrivyArgs: inputs.extraTrivyArgs,
    buildId: agent.buildId,
    scanIndex,
  };
}

function selectRunner(runners: RunnerConfig[], requested: string | undefined): RunnerConfig {
  const usable = runners.filter((runner) => runner.enabled !== false);

  if (runners.length === 0) {
    throw new RunnerNotFoundError(
      'The project has no runners configured. Add one in Project Settings > Trivy Scanner > Runners.',
    );
  }

  if (requested) {
    const match = usable.find((runner) => runner.alias === requested);
    if (!match) {
      throw new RunnerNotFoundError(
        `Runner "${requested}" is not available. Enabled runners: ${usable
          .map((runner) => runner.alias)
          .join(', ')}.`,
      );
    }
    return match;
  }

  const fallback = usable.find((runner) => runner.isDefault);
  if (!fallback) {
    throw new RunnerNotFoundError(
      'No default runner is configured. Mark one runner as default in Project Settings > Trivy Scanner > Runners, or set the "runner" input.',
    );
  }
  return fallback;
}
