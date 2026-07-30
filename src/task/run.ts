import * as fs from 'fs';
import * as path from 'path';
import { resolveConfig } from './ConfigResolver';
import {
  buildCopyInArgs,
  buildCopyOutArgs,
  buildFormatArgs,
  buildLoginArgs,
  buildRemoveArgs,
  buildScanArgs,
  buildStartArgs,
  buildTrivyEnv,
  buildVersionArgs,
  containerExtraPath,
  containerName,
  containerReportPath,
  extraNameSuffix,
  ExtraFormat,
  hostExtraPath,
  hostReportPath,
  registryHostFromImage,
  RegistryCredentials,
} from './DockerCommand';
import { removeEnvFile, writeEnvFile } from './EnvFile';
import { evaluateGate, GateResult } from './GateEvaluator';
import { buildJUnitXml } from './JUnitReport';
import { ProcessResult, ProcessRunner, RunOptions } from './ProcessRunner';
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
 * A real installation surfaced this as generic "docker exited with code 1 ... infrastructure
 * failure", which pointed nowhere useful: trivy's own message ("unable to write results: failed
 * to create a file: failed to create output file: open /workspace/.trivy/report-0.json: no such
 * file or directory") looks like a report-path bug in this task, and "Number of language-specific
 * files num=0" looks like an empty repository. Neither is true. `docker run -v
 * <sourcesDir>:/workspace` is resolved by the *docker daemon*, not by this process -- so when the
 * agent that invokes docker is itself containerised (a Kubernetes pod, say) and the daemon lives
 * in a different mount namespace (a sidecar daemon, or the host's daemon reached through a
 * mounted socket), the daemon cannot see the path the agent asked it to mount and silently
 * substitutes an empty directory instead of failing the mount outright. Trivy then finds zero
 * files and cannot even create its own report inside that empty mount, since `.trivy` (created on
 * the agent moments earlier, see createDirectoryOrThrow above) never actually appeared there from
 * the daemon's point of view.
 *
 * Matching is deliberately not on trivy's own sentence: that wording has already shifted across
 * releases for the database-download case above, so keying on it here would be equally brittle.
 * `containerReportPath` is this task's own literal, not trivy's, so it is far more stable, and
 * requiring that report file be genuinely absent on the host guards against a coincidental
 * mention of that path in an unrelated failure whose scan actually succeeded. "no such file or
 * directory" is the OS's own ENOENT rendering, not a trivy phrasing, and is the same durable
 * signal for the same reason. Both are required together, and confidence stays low without them:
 * a wrong diagnosis here would send someone chasing a daemon mount problem that does not exist,
 * which is worse than the generic message this falls through to when unsure.
 */
function isDaemonCannotSeeSourcesFailure(
  config: ResolvedScanConfig,
  scan: Pick<ProcessResult, 'stdout' | 'stderr'>,
): boolean {
  if (fs.existsSync(hostReportPath(config))) {
    return false;
  }
  const output = `${scan.stderr}\n${scan.stdout}`;
  return output.includes(containerReportPath(config)) && /no such file or directory/i.test(output);
}

function daemonCannotSeeSourcesMessage(
  config: ResolvedScanConfig,
  scan: Pick<ProcessResult, 'stdout' | 'stderr'>,
): string {
  return (
    `Trivy could not create its report at ${containerReportPath(config)} inside the container. ` +
    `This means the docker daemon could not see this agent's sources directory ` +
    `("${config.sourcesDir}") when it mounted it into the container. ` +
    '`docker run -v <sourcesDir>:/workspace` is resolved by the docker daemon, not by this task, ' +
    'so this happens when the agent itself runs in a container and the daemon lives in a ' +
    "different mount namespace -- a sidecar daemon, or the host's daemon reached through a " +
    'mounted socket -- in which case the daemon cannot see the path and silently mounts an ' +
    'empty directory instead. Check that the daemon and the agent see ' +
    `"${config.sourcesDir}" identically: either the same volume mounted at the same mountPath ` +
    "in both containers, or a host path mounted into the agent at that same location. " +
    'Alternatively, set the "sourceTransfer" input to "copy": it streams the sources into the ' +
    'container over the docker API instead of bind-mounting them, so it needs no shared ' +
    'filesystem between the agent and the daemon at all (at the cost of streaming the sources ' +
    'in on every scan and skipping the local vulnerability-database cache). ' +
    `Detail: ${scan.stderr.trim() || scan.stdout.trim()}`
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
 *
 * A failed login only warns; it does not abort the scan. A live installation disproved
 * the premise that used to justify treating this as fatal ("the pull would fail with a
 * worse message anyway"): a registry can permit anonymous pulls while still rejecting
 * `docker login` for a reason that has nothing to do with whether the pull will work
 * (e.g. a Nexus registry that has not enabled its Docker Bearer Token Realm, where login
 * cannot succeed with any credentials, yet a plain anonymous `docker pull` works fine).
 * So the scan proceeds exactly as if no credentials had been configured; if the pull
 * genuinely cannot happen, the scan's own docker-exit-code handling below reports that
 * with its own specific message, and this function must not pre-empt it.
 */
async function loginToRunnerRegistry(
  config: ResolvedScanConfig,
  processRunner: ProcessRunner,
  publisher: Publisher,
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
    publisher.warn(
      `docker login to registry "${host}" failed for runner "${config.runner.alias}": ` +
        `${result.stderr.trim() || result.stdout.trim() || `exit code ${result.exitCode}`}. ` +
        'Continuing without it: the scan will still be attempted, and the image pull may ' +
        'still succeed if the registry allows anonymous access.',
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

/**
 * Runs one containerized trivy invocation -- the JSON scan or an extra-format run -- and
 * returns the `ProcessResult` that represents the trivy execution itself, so every caller
 * (the exit-code/timeout handling in `runScan` below, and `emitExtraFormat`'s own) can stay
 * written against a single docker call's result regardless of `sourceTransfer`.
 *
 * `mount` mode: unchanged from before this function existed -- `setupArgs` (built by
 * `buildScanArgs`/`buildFormatArgs`) already is `docker run ...`, and this is a single
 * `processRunner.run` call with the same arguments and options a direct call would have
 * used, so `mount` mode's behavior is byte-for-byte identical to before.
 *
 * `copy` mode: `setupArgs` is `docker create ...` instead (no sources/cache mount, no
 * `--rm`). Sources are streamed in with `docker cp`, the container is started with
 * `docker start -a` -- the `-a` is what still propagates the exit code the caller depends
 * on -- and, only once that has finished, the output file is streamed back out with another
 * `docker cp`. `docker rm -f` always runs in the `finally`, whatever happened above, so a
 * failure at any step cannot leave the container behind. A failure at `create` or the
 * copy-in step short-circuits before ever starting the container, and is returned as-is for
 * the caller's existing generic-failure handling to report.
 */
async function runContainerized(
  config: ResolvedScanConfig,
  processRunner: ProcessRunner,
  setupArgs: string[],
  name: string,
  containerOutputPath: string,
  hostOutputPath: string,
  runOptions: RunOptions,
): Promise<ProcessResult> {
  if (config.sourceTransfer !== 'copy') {
    return processRunner.run('docker', setupArgs, runOptions);
  }

  try {
    const create = await processRunner.run('docker', setupArgs);
    if (create.exitCode !== 0) {
      return create;
    }

    const copyIn = await processRunner.run('docker', buildCopyInArgs(config.sourcesDir, name));
    if (copyIn.exitCode !== 0) {
      return copyIn;
    }

    const start = await processRunner.run('docker', buildStartArgs(name), runOptions);
    if (start.exitCode !== 0 || start.timedOut) {
      return start;
    }

    const copyOut = await processRunner.run(
      'docker',
      buildCopyOutArgs(name, containerOutputPath, hostOutputPath),
    );
    return copyOut.exitCode === 0 ? start : copyOut;
  } finally {
    await processRunner.run('docker', buildRemoveArgs(name));
  }
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
  // only warns (never throws) when the runner carries credentials but the login fails --
  // the scan still proceeds, since a registry can allow anonymous pulls even though
  // login itself fails for an unrelated reason. It is a no-op when the runner carries
  // no credentials at all.
  await loginToRunnerRegistry(config, processRunner, publisher);

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
    const scan = await runContainerized(
      config,
      processRunner,
      buildScanArgs(config, envFile),
      containerName(config),
      containerReportPath(config),
      hostReportPath(config),
      { timeoutMs, onStdout: (chunk) => process.stdout.write(chunk) },
    );

    if (scan.timedOut) {
      // In copy mode runContainerized's own `finally` already removed the container (it
      // never passes --rm to `docker create`, so removal only ever happens there); doing
      // it again here would just be a second, redundant `docker rm -f` against a
      // container that is already gone. In mount mode `docker run --rm` normally removes
      // the container on exit, but a SIGKILL from a timeout can race that cleanup, so the
      // explicit removal here stays for that mode exactly as before.
      if (config.sourceTransfer !== 'copy') {
        await processRunner.run('docker', buildRemoveArgs(containerName(config)));
      }
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
      if (isDaemonCannotSeeSourcesFailure(config, scan)) {
        throw new ScanExecutionError(daemonCannotSeeSourcesMessage(config, scan));
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
  if (config.publishTestResults) {
    // buildJUnitXml is a pure function over `report`, the already-parsed NormalizedReport this
    // process holds in memory -- not a second trivy invocation and not a new container round
    // trip. That matters specifically for `sourceTransfer: copy`: the report was already
    // streamed out of the container once (see runContainerized above) to produce `report` in
    // the first place, so this XML is generated entirely on the agent from data already here,
    // the same way the normalized-report attachment above is. Failing to write or publish it
    // only warns (like the sarif/sbom extra formats below-in-spirit): this is an opt-in
    // reporting convenience, not the gate, and a build that otherwise scanned successfully must
    // not fail because of it.
    const junitPath = path.join(config.sourcesDir, '.trivy', `junit-${config.scanIndex}.xml`);
    const runTitle = `Trivy - ${report.artifactName}`;
    try {
      fs.writeFileSync(junitPath, buildJUnitXml(report, { suiteName: runTitle }));
      publisher.publishJUnit(junitPath, runTitle);
    } catch (error) {
      publisher.warn(
        `Could not write the JUnit test-results file to "${junitPath}": ${(error as Error).message}. ` +
          'Test results were not published for this scan; the gate and every other output are unaffected.',
      );
    }
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
  let result: ProcessResult;
  try {
    result = await runContainerized(
      config,
      processRunner,
      buildFormatArgs(config, envFile, format),
      containerName(config, extraNameSuffix(format)),
      containerExtraPath(config, format),
      hostExtraPath(config, format),
      { timeoutMs },
    );
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
