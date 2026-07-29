import * as fs from 'fs';
import * as path from 'path';
import { resolveConfig } from './ConfigResolver';
import {
  buildFormatArgs,
  buildLoginArgs,
  buildScanArgs,
  buildTrivyEnv,
  buildVersionArgs,
  containerName,
  ExtraFormat,
  hostExtraPath,
  hostReportPath,
  registryHostFromImage,
  RegistryCredentials,
} from './DockerCommand';
import { removeEnvFile, writeEnvFile } from './EnvFile';
import { evaluateGate, GateResult } from './GateEvaluator';
import { ProcessResult, ProcessRunner } from './ProcessRunner';
import { Publisher } from './Publisher';
import { parseTrivyReport, parseVersion } from './ReportParser';
import {
  AgentContext,
  DefaultsConfig,
  NormalizedReport,
  ResolvedScanConfig,
  RunnerConfig,
  RunnerInfo,
  TaskInputs,
} from '../shared/types';

export class ScanExecutionError extends Error {}

function createDirectoryOrThrow(dirPath: string, description: string, extraGuidance: string): void {
  try {
    fs.mkdirSync(dirPath, { recursive: true });
  } catch (error) {
    const reason = (error as Error).message;
    throw new ScanExecutionError(
      `Could not create the ${description} at "${dirPath}": ${reason}.${extraGuidance ? ` ${extraGuidance}` : ''}`,
    );
  }
}

/**
 * ChildProcessRunner uses exit code 127 as a sentinel for *every* spawn failure -- ENOENT
 * (not found), EACCES (permission denied), or anything else the OS reports when it cannot
 * even start the child (see its own doc comment) -- so the code alone cannot tell "docker
 * is missing" apart from some other spawn problem. Node's own error message for the
 * not-found case always contains "ENOENT" (e.g. "spawn docker ENOENT") regardless of OS
 * or Node version, which is the durable signal checked here instead of assuming 127 always
 * means this.
 */
function isDockerNotFoundError(scan: Pick<ProcessResult, 'exitCode' | 'stderr'>): boolean {
  return scan.exitCode === 127 && /ENOENT/.test(scan.stderr);
}

function dockerNotFoundMessage(scan: Pick<ProcessResult, 'stderr'>): string {
  return (
    "This agent has no docker on its PATH (spawn docker ENOENT). This task runs trivy inside " +
    'a container and requires docker on the agent; it cannot fall back to a local trivy ' +
    `install by design. Install docker on this agent, or route the pipeline to one that ` +
    `already has it. Detail: ${scan.stderr.trim()}`
  );
}

/**
 * Trivy's own wording for a failed database download has shifted across releases ("DB
 * error: failed to download vulnerability DB", "init error: DB error: failed to download
 * vulnerability DB", "OCI artifact error" vs "OCI repository error", ...), but every
 * version of that message has kept this substring, so it is the durable signal to match
 * on rather than a specific release's exact phrasing. Checking both streams because a
 * fatal trivy error can land on either depending on how it was raised.
 */
function isDbDownloadFailure(scan: Pick<ProcessResult, 'stdout' | 'stderr'>): boolean {
  return /failed to download vulnerability db/i.test(`${scan.stderr}\n${scan.stdout}`);
}

function dbDownloadFailureMessage(
  config: ResolvedScanConfig,
  credentials: RegistryCredentials,
): string {
  const credentialNote =
    credentials.username || credentials.password
      ? 'credentials were supplied'
      : 'no credentials were supplied';
  return (
    `The vulnerability database could not be downloaded from dbRepository "${config.dbRepository}" ` +
    `(${credentialNote}). Check that this agent can reach that registry and that any required ` +
    'credentials are configured for it.'
  );
}

/**
 * Logs in to the registry hosting the selected runner's image, when an administrator
 * entered credentials for it in the settings document (`RunnerConfig.registryUsername` /
 * `registryPassword`). Both fields are optional together and `validateRunner` rejects one
 * without the other, so here either both are present or neither is - there is no partial
 * case to handle.
 *
 * Runs before the version probe and the scan (both of which pull the image), because a
 * private registry that requires auth would otherwise fail the pull with a confusing
 * `docker exited with code 125` rather than this named failure. The password reaches
 * docker only through `RunOptions.stdin` (`--password-stdin`), never through argv.
 */
async function loginToRunnerRegistry(
  config: ResolvedScanConfig,
  processRunner: ProcessRunner,
): Promise<void> {
  const { registryUsername: username, registryPassword: password } = config.runner;
  if (!username || !password) {
    return;
  }

  const host = registryHostFromImage(config.runner.image);
  const result = await processRunner.run('docker', buildLoginArgs(host, username), {
    stdin: password,
  });

  if (result.exitCode !== 0) {
    throw new ScanExecutionError(
      `docker login to registry "${host}" failed for runner "${config.runner.alias}": ` +
        `${result.stderr.trim() || result.stdout.trim() || `exit code ${result.exitCode}`}. ` +
        'The scan was not attempted, since the image pull would fail with a worse message anyway.',
    );
  }
}

/**
 * Trivy pulls the vulnerability database from *inside* the container, so a host-side
 * `docker login` (see `loginToRunnerRegistry` above) cannot help it: it reads
 * `TRIVY_USERNAME`/`TRIVY_PASSWORD` from its own environment instead, and those same two
 * variables are already how the *scanned image's* credentials
 * (`TaskInputs.targetRegistryConnection`, resolved by `index.ts` into `RunScanArgs.credentials`)
 * reach trivy for a private-registry `image` scan. Trivy has no second pair of variables and
 * this task deliberately does not attempt per-registry credential mapping through repeated
 * trivy flags (fragile, and the common on-prem case is one corporate registry for
 * everything) - so when both sources are configured, only one can actually be presented,
 * and the choice must be explicit rather than one silently overwriting the other:
 * the target image's credentials win, since they are specific to *this* scan, and the
 * database-mirror credentials are dropped with a warning explaining why.
 */
function resolveTrivyCredentials(
  defaults: DefaultsConfig,
  targetCredentials: RegistryCredentials,
  publisher: Publisher,
): RegistryCredentials {
  const hasTargetCredentials = Boolean(targetCredentials.username || targetCredentials.password);
  const hasDbMirrorCredentials = Boolean(
    defaults.dbRegistryUsername || defaults.dbRegistryPassword,
  );

  if (hasTargetCredentials && hasDbMirrorCredentials) {
    publisher.warn(
      'Both a target-image registry connection (targetRegistryConnection) and database-mirror ' +
        'credentials (dbRegistryUsername/dbRegistryPassword) are configured. Trivy reads a ' +
        'single TRIVY_USERNAME/TRIVY_PASSWORD pair from its environment for both purposes, so ' +
        'only one can be presented for this scan: the target image credentials are used, and ' +
        'the database-mirror credentials are ignored.',
    );
    return targetCredentials;
  }

  if (hasTargetCredentials) {
    return targetCredentials;
  }

  return { username: defaults.dbRegistryUsername, password: defaults.dbRegistryPassword };
}

export interface RunScanArgs {
  defaults: DefaultsConfig;
  runners: RunnerConfig[];
  inputs: TaskInputs;
  agent: AgentContext;
  scanIndex: number;
  processRunner: ProcessRunner;
  publisher: Publisher;
  credentials: RegistryCredentials;
}

export interface RunScanResult {
  report: NormalizedReport;
  gate: GateResult;
  /** Path to trivy's own raw JSON report -- this is what the TrivyReports artifact carries. */
  reportPath: string;
  /** Path to the normalized report -- this is what the results-tab attachment carries. */
  normalizedReportPath: string;
}

export async function runScan(args: RunScanArgs): Promise<RunScanResult> {
  const { processRunner, publisher } = args;
  const config = resolveConfig({
    defaults: args.defaults,
    runners: args.runners,
    inputs: args.inputs,
    agent: args.agent,
    scanIndex: args.scanIndex,
  });

  // Created before the version probe below: buildVersionArgs bind-mounts cacheDir, and if
  // that directory does not exist yet, docker itself creates it on a first run -- as root.
  // Creating it here first means it is always this task (not the docker daemon) that
  // creates it, so the "an administrator can change it" guidance in the message below
  // actually applies from the very first run.
  createDirectoryOrThrow(
    config.cacheDir,
    'trivy cache directory',
    "This path comes from the collection's Trivy settings (cacheDir) - an administrator can change it there.",
  );

  // Before the version probe and the scan below, both of which pull the runner image: a
  // private registry that needs auth would otherwise fail the pull with an opaque
  // "docker exited with code 125" instead of this named failure. loginToRunnerRegistry
  // itself throws (aborting the scan) when the runner carries credentials but the login
  // fails; it is a no-op when the runner carries none.
  await loginToRunnerRegistry(config, processRunner);

  // Resolved once, before the version probe, since the message dbDownloadFailureMessage
  // builds below (on the scan path) and the env file (also below) both need the same
  // decision about which credentials actually reached TRIVY_USERNAME/TRIVY_PASSWORD.
  const trivyCredentials = resolveTrivyCredentials(args.defaults, args.credentials, publisher);

  // The version probe is decoration (see ReportParser.parseVersion): a garbled response
  // already cannot fail the scan below, and neither can the probe call itself throwing
  // outright -- e.g. a ProcessRunner implementation that rejects instead of resolving
  // with a non-zero exit code, which the real ChildProcessRunner never does but nothing
  // in the ProcessRunner interface forbids. Losing the version and database date is
  // visible (a warning), not silent, but it must never cost a scan that otherwise worked.
  let runnerInfo: RunnerInfo = { alias: config.runner.alias, image: config.runner.image };
  try {
    const version = await processRunner.run('docker', buildVersionArgs(config));
    runnerInfo = { ...runnerInfo, ...parseVersion(version.stdout) };
  } catch (error) {
    publisher.warn(
      `Trivy version probe failed: the report will not record the trivy version or database date. Reason: ${(error as Error).message}`,
    );
  }

  createDirectoryOrThrow(path.join(config.sourcesDir, '.trivy'), 'report output directory', '');

  const envFile = writeEnvFile(
    args.agent.tempDir,
    `scan-${config.scanIndex}`,
    buildTrivyEnv(config, trivyCredentials),
  );
  const timeoutMs = config.timeoutMinutes * 60_000 + 30_000;

  try {
    // buildScanArgs always requests `--format json --output <path>`: the gate
    // (evaluateGate below) and the normalized-report attachment both depend on parsing
    // that file, so the JSON run is not optional and does not live behind `formats`.
    // `formats` therefore only selects which *additional* outputs (the table log, sarif)
    // are produced alongside it -- listing or omitting 'json' in `formats` has no effect,
    // by design.
    const scan = await processRunner.run('docker', buildScanArgs(config, envFile), {
      timeoutMs,
      onStdout: (chunk) => process.stdout.write(chunk),
    });

    if (scan.timedOut) {
      await processRunner.run('docker', ['rm', '-f', containerName(config)]);
      throw new ScanExecutionError(
        `The scan exceeded ${config.timeoutMinutes} minutes and was killed. Raise the timeoutMinutes input or the collection default.`,
      );
    }

    if (scan.exitCode !== 0) {
      // A non-zero docker exit is an infrastructure failure (docker itself could not
      // run the container), never "the scan found vulnerabilities" -- trivy always runs
      // with --exit-code 0 for exactly that reason, so the gate is the only thing that
      // can fail a build over findings. Two specific classes get a named, actionable
      // message instead of the generic one below; anything else falls through to it
      // rather than being mislabelled.
      if (isDockerNotFoundError(scan)) {
        throw new ScanExecutionError(dockerNotFoundMessage(scan));
      }
      if (isDbDownloadFailure(scan)) {
        throw new ScanExecutionError(dbDownloadFailureMessage(config, trivyCredentials));
      }
      throw new ScanExecutionError(
        `docker exited with code ${scan.exitCode} while running ${config.runner.image}. ` +
          `This is an infrastructure failure, not a scan result. Output: ${scan.stderr.trim() || scan.stdout.trim()}`,
      );
    }

    // Extra formats reuse this same env file (same registry credentials, same TRIVY_*
    // vars as the JSON scan) and must run while it still exists. It is removed exactly
    // once, in the `finally` below, after every docker invocation for this scan -- the
    // JSON scan and any extra-format runs -- has finished.
    if (config.formats.includes('sarif')) {
      await emitExtraFormat(config, envFile, 'sarif', timeoutMs, processRunner, publisher, (host) =>
        publisher.publishSarif(host),
      );
    }
    if (config.generateSbom !== 'off') {
      await emitExtraFormat(
        config,
        envFile,
        config.generateSbom,
        timeoutMs,
        processRunner,
        publisher,
        (host) => publisher.publishArtifact(host, 'TrivySBOM'),
      );
    }
  } finally {
    // The env file holds registry credentials: it must be gone whether the scan
    // succeeded, failed, an extra-format run failed, or any process runner call above
    // threw outright. removeEnvFile itself never throws (a delete failure must not
    // replace the real scan outcome from the try above), so a failed removal is only
    // reported if this callback is wired up -- without it the credentials file is left
    // on disk with nothing anywhere saying so.
    removeEnvFile(envFile, (message) => publisher.warn(message));
  }

  const reportPath = hostReportPath(config);
  if (!fs.existsSync(reportPath)) {
    throw new ScanExecutionError(
      `Runner ${config.runner.image} did not produce a report at ${reportPath}. Check that the image entrypoint is trivy.`,
    );
  }

  const report = parseTrivyReport(fs.readFileSync(reportPath, 'utf8'), {
    scanType: config.scanType,
    target: config.target,
    runner: runnerInfo,
  });

  // UNKNOWN ranks lowest and FailOn excludes it as a threshold, so any finding degraded
  // to UNKNOWN because trivy used a severity label this task does not recognize is
  // structurally incapable of failing the gate. That must be visible, not silent -- a
  // future trivy release renaming or adding a label would otherwise make the gate go
  // green with nobody the wiser.
  if (report.unrecognizedSeverities.length > 0) {
    publisher.warn(
      `Trivy reported unrecognized severity label(s): ${report.unrecognizedSeverities.join(', ')}. Findings carrying them were treated as UNKNOWN severity and therefore cannot fail the gate.`,
    );
  }

  const gate = evaluateGate(report, config.failOn);

  // The attachment below is the contract the results-tab plan depends on: schemaVersion,
  // artifactName, kindCounts, each finding's kind, and (via `report.runner`) the runner
  // alias, trivy version and database date -- none of which exist in trivy's own raw JSON
  // (report-0.json, still published separately below as the TrivyReports artifact). Only
  // the fields NormalizedReport actually declares are written here: `report` itself also
  // carries `unrecognizedSeverities` (ReportParser's own extension), which is not part of
  // that contract and must not leak into the file the results tab is meant to read.
  const normalizedReportPath = path.join(config.sourcesDir, '.trivy', `normalized-${config.scanIndex}.json`);
  const normalizedReport: NormalizedReport = {
    schemaVersion: report.schemaVersion,
    scanType: report.scanType,
    target: report.target,
    artifactName: report.artifactName,
    ...(report.createdAt !== undefined ? { createdAt: report.createdAt } : {}),
    runner: report.runner,
    findings: report.findings,
    counts: report.counts,
    kindCounts: report.kindCounts,
  };
  try {
    fs.writeFileSync(normalizedReportPath, JSON.stringify(normalizedReport));
  } catch (error) {
    // Loud and fatal, unlike the env-file removal failure above: that file is a leftover
    // to warn about, this one is the attachment the next plan is built on, so a build that
    // cannot produce it must not quietly report success.
    throw new ScanExecutionError(
      `Could not write the normalized report to "${normalizedReportPath}": ${(error as Error).message}. ` +
        'The results-tab attachment depends on this file, so the scan cannot continue without it.',
    );
  }

  publisher.printSummary(report, config.runner.alias);
  if (config.formats.includes('table')) {
    publisher.printFindingsTable(report);
  }
  publisher.attachReport(normalizedReportPath, config.scanIndex);
  if (config.publishArtifact) {
    // Unlike the attachment above, a user downloading build results wants trivy's own
    // output -- that is what "TrivyReports" has always meant -- so this stays the raw file.
    publisher.publishArtifact(reportPath, 'TrivyReports');
  }
  if (gate.blocking.length > 0) {
    publisher.logBlockingFindings(gate.blocking);
  }

  return { report, gate, reportPath, normalizedReportPath };
}

/**
 * An extra format is a convenience, not the gate: the JSON report parsed above is what
 * the gate and the results tab depend on, so a problem producing SARIF or an SBOM -- a
 * non-zero docker exit, a missing output file, or the process runner call itself
 * rejecting outright (the same possibility already handled for the version probe above,
 * since nothing in the ProcessRunner interface forbids it) -- is reported as a warning
 * and must never fail the scan.
 */
async function emitExtraFormat(
  config: ResolvedScanConfig,
  envFile: string,
  format: ExtraFormat,
  timeoutMs: number,
  processRunner: ProcessRunner,
  publisher: Publisher,
  publish: (hostPath: string) => void,
): Promise<void> {
  let result;
  try {
    result = await processRunner.run('docker', buildFormatArgs(config, envFile, format), {
      timeoutMs,
    });
  } catch (error) {
    publisher.warn(
      `Could not produce the ${format} output: ${(error as Error).message}. The scan result itself is unaffected.`,
    );
    return;
  }

  const hostPath = hostExtraPath(config, format);
  if (result.exitCode !== 0 || !fs.existsSync(hostPath)) {
    publisher.warn(
      `Could not produce the ${format} output: ${result.stderr.trim() || 'no file was written'}. The scan result itself is unaffected.`,
    );
    return;
  }

  publish(hostPath);
}
