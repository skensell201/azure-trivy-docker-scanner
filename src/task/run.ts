import * as fs from 'fs';
import * as path from 'path';
import { resolveConfig } from './ConfigResolver';
import {
  buildFormatArgs,
  buildScanArgs,
  buildTrivyEnv,
  buildVersionArgs,
  containerName,
  ExtraFormat,
  hostExtraPath,
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
    publisher.warn(
      `Trivy version probe failed: the report will not record the trivy version or database date. Reason: ${(error as Error).message}`,
    );
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
  const timeoutMs = config.timeoutMinutes * 60_000 + 30_000;

  try {
    const scan = await processRunner.run('docker', buildScanArgs(config, envFile), {
      timeoutMs,
      onStdout: (chunk) => process.stdout.write(chunk),
    });

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

  publisher.printSummary(report, config.runner.alias);
  if (config.formats.includes('table')) {
    publisher.printFindingsTable(report);
  }
  publisher.attachReport(reportPath, config.scanIndex);
  if (config.publishArtifact) {
    publisher.publishArtifact(reportPath, 'TrivyReports');
  }
  if (gate.blocking.length > 0) {
    publisher.logBlockingFindings(gate.blocking);
  }

  return { report, gate, reportPath };
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
