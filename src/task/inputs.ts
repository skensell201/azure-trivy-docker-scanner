import * as tl from 'azure-pipelines-task-lib/task';
import { parseSeverity, parseSeverityList } from '../shared/severity';
import {
  FailOn,
  OutputFormat,
  SbomFormat,
  Scanner,
  ScanType,
  TaskInputs,
} from '../shared/types';

const SCAN_TYPES: ScanType[] = ['image', 'filesystem', 'repository', 'config', 'sbom'];
const SCANNERS: Scanner[] = ['vuln', 'secret', 'misconfig', 'license'];
const FORMATS: OutputFormat[] = ['table', 'json', 'sarif'];
const SBOM_FORMATS: SbomFormat[] = ['off', 'cyclonedx', 'spdx-json'];

function oneOf<T extends string>(name: string, raw: string, allowed: T[]): T {
  const value = raw.trim() as T;
  if (!allowed.includes(value)) {
    throw new Error(`Input "${name}" has value "${raw}". Allowed values: ${allowed.join(', ')}.`);
  }
  return value;
}

function listOf<T extends string>(name: string, raw: string, allowed: T[]): T[] {
  return raw
    .split(',')
    .map((part) => part.trim())
    .filter((part) => part.length > 0)
    .map((part) => oneOf(name, part, allowed));
}

/** Set the boolean only when the pipeline provided it, so admin defaults still apply.
 * `getBoolInput` returns `false` for an input the pipeline never set, which is
 * indistinguishable from an explicit `false` — checking `getInput` first tells them apart. */
function optionalBool(name: string): boolean | undefined {
  return tl.getInput(name) === undefined ? undefined : tl.getBoolInput(name);
}

/**
 * `failOn` accepts 'none' plus every Severity except 'UNKNOWN'. `parseSeverity` alone
 * would accept 'UNKNOWN' (it is a valid finding severity), so it is rejected explicitly
 * here rather than laundered through a type cast: as a threshold it would fail the build
 * on every finding, including ones Trivy could not score.
 */
function parseFailOn(raw: string): FailOn {
  if (raw.trim().toLowerCase() === 'none') {
    return 'none';
  }
  const severity = parseSeverity(raw);
  if (severity === 'UNKNOWN') {
    throw new Error(
      'Input "failOn" cannot be "UNKNOWN": it is a valid finding severity but a meaningless ' +
        'threshold, since it would fail the build on every finding, including ones Trivy could ' +
        'not score. Use "none" to disable the gate, or one of: LOW, MEDIUM, HIGH, CRITICAL.',
    );
  }
  return severity;
}

export function readInputs(): TaskInputs {
  const scanTypeRaw = tl.getInput('scanType') ?? 'image';
  const target = tl.getInput('target');
  if (!target) {
    throw new Error('Input "target" is required: pass an image reference or a path to scan.');
  }

  const severitiesRaw = tl.getInput('severities');
  const scannersRaw = tl.getInput('scanners');
  const failOnRaw = tl.getInput('failOn');
  const timeoutRaw = tl.getInput('timeoutMinutes');
  const formatsRaw = tl.getInput('formats');
  const sbomRaw = tl.getInput('generateSbom');

  let timeoutMinutes: number | undefined;
  if (timeoutRaw !== undefined) {
    timeoutMinutes = Number(timeoutRaw);
    if (!Number.isFinite(timeoutMinutes) || timeoutMinutes <= 0) {
      throw new Error(`Input "timeoutMinutes" must be a positive number, got "${timeoutRaw}".`);
    }
  }

  const failOn: FailOn | undefined = failOnRaw === undefined ? undefined : parseFailOn(failOnRaw);

  return {
    scanType: oneOf('scanType', scanTypeRaw, SCAN_TYPES),
    target,
    runner: tl.getInput('runner'),
    severities: severitiesRaw === undefined ? undefined : parseSeverityList(severitiesRaw),
    scanners: scannersRaw === undefined ? undefined : listOf('scanners', scannersRaw, SCANNERS),
    failOn,
    ignoreUnfixed: optionalBool('ignoreUnfixed'),
    ignoreFile: tl.getInput('ignoreFile'),
    timeoutMinutes,
    skipDbUpdate: optionalBool('skipDbUpdate'),
    targetRegistryConnection: tl.getInput('targetRegistryConnection'),
    useDockerSocket: optionalBool('useDockerSocket'),
    formats: formatsRaw === undefined ? undefined : listOf('formats', formatsRaw, FORMATS),
    generateSbom: sbomRaw === undefined ? undefined : oneOf('generateSbom', sbomRaw, SBOM_FORMATS),
    publishArtifact: optionalBool('publishArtifact'),
    extraTrivyArgs: tl.getInput('extraTrivyArgs'),
    workingDirectory: tl.getInput('workingDirectory'),
  };
}
