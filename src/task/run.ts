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
  TaskInputs,
} from '../shared/types';

export class ScanExecutionError extends Error {}

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

  // The version probe is decoration (see ReportParser.parseVersion): its own failure
  // must never fail the scan, so its result is not checked here at all.
  const version = await processRunner.run('docker', buildVersionArgs(config));
  const runnerInfo = {
    alias: config.runner.alias,
    image: config.runner.image,
    ...parseVersion(version.stdout),
  };

  fs.mkdirSync(config.cacheDir, { recursive: true });
  fs.mkdirSync(path.join(config.sourcesDir, '.trivy'), { recursive: true });

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
