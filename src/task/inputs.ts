import * as tl from 'azure-pipelines-task-lib/task';
import { parseSeverity, parseSeverityList } from '../shared/severity';
import {
  FailOn,
  OutputFormat,
  SbomFormat,
  Scanner,
  ScanType,
  SourceTransfer,
  Severity,
  TaskInputs,
} from '../shared/types';

const SCAN_TYPES: ScanType[] = ['image', 'filesystem', 'repository', 'config', 'sbom'];
const SCANNERS: Scanner[] = ['vuln', 'secret', 'misconfig', 'license'];
const FORMATS: OutputFormat[] = ['table', 'json', 'sarif'];
const SBOM_FORMATS: SbomFormat[] = ['off', 'cyclonedx', 'spdx-json'];
const SOURCE_TRANSFERS: SourceTransfer[] = ['mount', 'copy'];

// Every vocabulary this module validates against is lowercase, so a value that merely differs
// in case (e.g. "Vuln", "Image") is normalized rather than treated as a hard failure alongside
// genuinely unknown values.
function oneOf<T extends string>(name: string, raw: string, allowed: T[]): T {
  const value = raw.trim().toLowerCase() as T;
  if (!allowed.includes(value)) {
    throw new Error(`Input "${name}" has value "${raw}". Allowed values: ${allowed.join(', ')}.`);
  }
  return value;
}

function listOf<T extends string>(name: string, raw: string, allowed: T[]): T[] {
  const parts = raw
    .split(',')
    .map((part) => part.trim())
    .filter((part) => part.length > 0)
    .map((part) => oneOf(name, part, allowed));

  // A list that is blank, or blank after trimming (e.g. a pipeline variable substitution that
  // resolved to a single space), must not silently become `[]`. Unlike `undefined`, an empty
  // array reaches ConfigResolver as a real override and discards the administrator's setting —
  // for `formats` it also defeats the `?? ['table','json']` fallback, producing a scan that
  // writes no report at all.
  if (parts.length === 0) {
    throw new Error(`Input "${name}" must contain at least one value, got "${raw}".`);
  }

  return parts;
}

/** Set the boolean only when the pipeline provided it, so admin defaults still apply.
 * `getBoolInput` returns `false` for an input the pipeline never set, which is
 * indistinguishable from an explicit `false` — checking `getInput` first tells them apart. */
function optionalBool(name: string): boolean | undefined {
  return tl.getInput(name) === undefined ? undefined : tl.getBoolInput(name);
}

/** Trims a free-text passthrough input so a stray leading/trailing space from copy-pasting a
 * pipeline variable does not surface as a confusing error several modules downstream (e.g.
 * `runner: " hardened "` failing ConfigResolver's lookup with a runner name nobody wrote). */
function trimmedInput(name: string): string | undefined {
  return tl.getInput(name)?.trim();
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

  let severity: Severity;
  try {
    severity = parseSeverity(raw);
  } catch {
    // Not `parseSeverity`'s own message: that vocabulary includes UNKNOWN (rejected below) and
    // omits "none" (accepted above), and it never names the input, which matters once a
    // pipeline has more than one severity-shaped input to get wrong.
    throw new Error(
      `Input "failOn" has value "${raw}". Allowed values: none, LOW, MEDIUM, HIGH, CRITICAL.`,
    );
  }

  if (severity === 'UNKNOWN') {
    throw new Error(
      'Input "failOn" cannot be "UNKNOWN": it is a valid finding severity but a meaningless ' +
        'threshold, since it would fail the build on every finding, including ones Trivy could ' +
        'not score. Use "none" to disable the gate, or one of: LOW, MEDIUM, HIGH, CRITICAL.',
    );
  }
  return severity;
}

/** Wraps `parseSeverityList` to name the input in the error: its own message only names the
 * offending value, which is ambiguous once a pipeline sets both `severities` and `failOn`. */
function parseSeveritiesInput(raw: string): Severity[] {
  try {
    return parseSeverityList(raw);
  } catch (error) {
    throw new Error(`Input "severities" has value "${raw}": ${(error as Error).message}`);
  }
}

/**
 * Reads and validates the task's pipeline inputs. This is the only module allowed to know about
 * `azure-pipelines-task-lib`; everything else in the task takes plain `TaskInputs` data.
 *
 * Central contract: an input the pipeline did not set comes back as `undefined`, never a
 * built-in default — defaults are `ConfigResolver`'s job, applied on top of the administrator's
 * settings. This holds only if `task.json` declares no `defaultValue` for any input handled here
 * (the exception is `scanType`, defaulted explicitly in code below). The agent materializes a
 * declared `defaultValue` into the `INPUT_*` environment variable as a non-empty string on every
 * run, so `getInput` would return it even when the pipeline author wrote nothing — indistinguishable
 * from an explicit value. `ConfigResolver` would then either silently override the administrator's
 * policy or, under a restrictive `allowOverrides`, fail every build naming a field nobody actually
 * set. This module has no way to detect that from here; whoever writes `task.json` must know it.
 */
export function readInputs(): TaskInputs {
  const scanTypeRaw = tl.getInput('scanType') ?? 'image';
  // Deliberately not trimmed, unlike the free-text inputs below: `target` is echoed verbatim
  // in report/artifact naming, and silently rewriting it could hide a pipeline author's mistake
  // (e.g. a stray space from a bad variable substitution) instead of surfacing it downstream.
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
  const sourceTransferRaw = tl.getInput('sourceTransfer');

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
    runner: trimmedInput('runner'),
    severities: severitiesRaw === undefined ? undefined : parseSeveritiesInput(severitiesRaw),
    scanners: scannersRaw === undefined ? undefined : listOf('scanners', scannersRaw, SCANNERS),
    failOn,
    ignoreUnfixed: optionalBool('ignoreUnfixed'),
    ignoreFile: trimmedInput('ignoreFile'),
    timeoutMinutes,
    skipDbUpdate: optionalBool('skipDbUpdate'),
    targetRegistryConnection: trimmedInput('targetRegistryConnection'),
    useDockerSocket: optionalBool('useDockerSocket'),
    formats: formatsRaw === undefined ? undefined : listOf('formats', formatsRaw, FORMATS),
    generateSbom: sbomRaw === undefined ? undefined : oneOf('generateSbom', sbomRaw, SBOM_FORMATS),
    publishArtifact: optionalBool('publishArtifact'),
    extraTrivyArgs: tl.getInput('extraTrivyArgs'),
    workingDirectory: trimmedInput('workingDirectory'),
    sourceTransfer:
      sourceTransferRaw === undefined
        ? undefined
        : oneOf('sourceTransfer', sourceTransferRaw, SOURCE_TRANSFERS),
  };
}
