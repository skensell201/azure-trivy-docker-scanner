import * as fs from 'fs';
import * as path from 'path';
import { resolveConfig } from './ConfigResolver';
import {
  buildScanArgs,
  buildTrivyEnv,
  buildVersionArgs,
  containerName,
  hostReportPath,
  RegistryCredentials,
} from './DockerCommand';
import { removeEnvFile, writeEnvFile } from './EnvFile';
import { evaluateGate, GateResult } from './GateEvaluator';
import { ProcessRunner } from './ProcessRunner';
import { Publisher } from './Publisher';
import { parseTrivyReport, parseVersion } from './ReportParser';
import {
  AgentContext,
  DefaultsConfig,
  NormalizedReport,
  RunnerConfig,
  RunnerInfo,
  TaskInputs,
} from '../shared/types';

export class ScanExecutionError extends Error {}

/**
 * Task 15b is expected to add a public `warn` method to Publisher for exactly this kind
 * of message. Until it lands, this module cannot add one itself (Publisher.ts is owned
 * by other in-flight work), so it detects the method at runtime and, failing that,
 * falls back to the LineWriter Publisher already wraps internally. Reaching past
 * Publisher's `private` modifier this way is not pretty, but it is what keeps this
 * warning visible through whatever sink a caller gave Publisher (a test's array, a log
 * file, ...) instead of silently going to `console.log` regardless of what the caller
 * asked for. `console.log` remains only as a last-resort fallback if neither surface is
 * present. Once Publisher grows `warn`, the two fallback branches simply stop firing.
 */
function emitVersionProbeWarning(publisher: Publisher, reason: string): void {
  const message = `Trivy version probe failed: the report will not record the trivy version or database date. Reason: ${sanitizeForWarningLine(reason)}`;
  const line = `##vso[task.logissue type=warning]${message}`;
  const surface = publisher as unknown as {
    warn?: (text: string) => void;
    write?: (text: string) => void;
  };
  if (typeof surface.warn === 'function') {
    surface.warn(message);
    return;
  }
  if (typeof surface.write === 'function') {
    surface.write(line);
    return;
  }
  console.log(line);
}

/**
 * Mirrors Publisher's own sanitizeForLogLine: `reason` comes from a caught error's
 * message, which can originate in process stderr this task does not control, so it
 * gets the same two defenses before reaching a `##vso[...]` log line -- a raw newline
 * would start a second physical line, and a literal "##vso[" in that second line would
 * be executed as a command of the error's choosing.
 */
function sanitizeForWarningLine(text: string): string {
  return text
    .replace(/\r\n|\r|\n/g, ' ')
    .replace(/##vso\[/gi, '#-vso[')
    .replace(/\s+/g, ' ')
    .trim();
}

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
  reportPath: string;
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
    emitVersionProbeWarning(publisher, (error as Error).message);
  }

  createDirectoryOrThrow(
    config.cacheDir,
    'trivy cache directory',
    "This path comes from the project's Trivy settings (cacheDir) - an administrator can change it there.",
  );
  createDirectoryOrThrow(path.join(config.sourcesDir, '.trivy'), 'report output directory', '');

  const envFile = writeEnvFile(
    args.agent.tempDir,
    `scan-${config.scanIndex}`,
    buildTrivyEnv(config, args.credentials),
  );

  let scan;
  try {
    scan = await processRunner.run('docker', buildScanArgs(config, envFile), {
      timeoutMs: config.timeoutMinutes * 60_000 + 30_000,
      onStdout: (chunk) => process.stdout.write(chunk),
    });
  } finally {
    // The env file holds registry credentials: it must be gone whether the scan
    // succeeded, failed, or the process runner itself threw.
    removeEnvFile(envFile);
  }

  if (scan.timedOut) {
    await processRunner.run('docker', ['rm', '-f', containerName(config)]);
    throw new ScanExecutionError(
      `The scan exceeded ${config.timeoutMinutes} minutes and was killed. Raise the timeoutMinutes input or the project default.`,
    );
  }

  if (scan.exitCode !== 0) {
    // A non-zero docker exit is an infrastructure failure (docker itself could not
    // run the container), never "the scan found vulnerabilities" -- trivy always runs
    // with --exit-code 0 for exactly that reason, so the gate is the only thing that
    // can fail a build over findings.
    throw new ScanExecutionError(
      `docker exited with code ${scan.exitCode} while running ${config.runner.image}. ` +
        `This is an infrastructure failure, not a scan result. Output: ${scan.stderr.trim() || scan.stdout.trim()}`,
    );
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

  const gate = evaluateGate(report, config.failOn);

  publisher.printSummary(report, config.runner.alias);
  publisher.attachReport(reportPath, config.scanIndex);
  if (gate.blocking.length > 0) {
    publisher.logBlockingFindings(gate.blocking);
  }

  return { report, gate, reportPath };
}
