import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { runScan } from '../run';
import { ProcessResult, ProcessRunner, RunOptions } from '../ProcessRunner';
import { Publisher } from '../Publisher';
import { AgentContext, DefaultsConfig, RunnerConfig, TaskInputs } from '../../shared/types';

class FakeRunner implements ProcessRunner {
  calls: { command: string; args: string[]; options?: RunOptions }[] = [];
  results: ProcessResult[] = [];

  constructor(private readonly onScan?: () => void) {}

  run(command: string, args: string[], options?: RunOptions): Promise<ProcessResult> {
    this.calls.push({ command, args, options });
    if (args.includes('version')) {
      return Promise.resolve({
        exitCode: 0,
        stdout: '{"Version":"0.58.1","VulnerabilityDB":{"UpdatedAt":"2026-07-28T06:11:53Z"}}',
        stderr: '',
        timedOut: false,
      });
    }
    this.onScan?.();
    return Promise.resolve(
      this.results.shift() ?? { exitCode: 0, stdout: '', stderr: '', timedOut: false },
    );
  }
}

const runners: RunnerConfig[] = [
  { alias: 'baseline', image: 'reg.corp/trivy:0.58.1', isDefault: true, enabled: true },
];
const defaults: DefaultsConfig = { dbRepository: 'reg.corp/trivy-db:2' };
const inputs: TaskInputs = { scanType: 'image', target: 'app:1.4.2' };

let workspace: string;
let agent: AgentContext;
let lines: string[];

const reportBody = JSON.stringify({
  SchemaVersion: 2,
  ArtifactName: 'app:1.4.2',
  Results: [
    {
      Target: 'app:1.4.2',
      Vulnerabilities: [
        { VulnerabilityID: 'CVE-1', PkgName: 'runc', Severity: 'CRITICAL', Title: 'escape' },
      ],
    },
  ],
});

const writeReport = () => {
  fs.mkdirSync(path.join(workspace, '.trivy'), { recursive: true });
  fs.writeFileSync(path.join(workspace, '.trivy', 'report-0.json'), reportBody);
};

beforeEach(() => {
  workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'run-'));
  fs.mkdirSync(path.join(workspace, 'temp'), { recursive: true });
  agent = {
    sourcesDir: workspace,
    agentHomeDir: workspace,
    tempDir: path.join(workspace, 'temp'),
    buildId: '1042',
  };
  lines = [];
});

afterEach(() => {
  fs.rmSync(workspace, { recursive: true, force: true });
});

const invoke = (runner: ProcessRunner) =>
  runScan({
    defaults,
    runners,
    inputs,
    agent,
    scanIndex: 0,
    processRunner: runner,
    publisher: new Publisher((line) => lines.push(line)),
    credentials: {},
  });

describe('runScan', () => {
  it('probes the runner version and then runs the scan', async () => {
    const runner = new FakeRunner(writeReport);
    await invoke(runner);
    expect(runner.calls[0].args).toContain('version');
    expect(runner.calls[1].args).toContain('image');
  });

  it('returns a failed gate when a critical finding is present', async () => {
    const result = await invoke(new FakeRunner(writeReport));
    expect(result.gate.outcome).toBe('failed');
    expect(result.report.findings).toHaveLength(1);
  });

  it('records the runner version and database timestamp in the report', async () => {
    const result = await invoke(new FakeRunner(writeReport));
    expect(result.report.runner).toMatchObject({
      trivyVersion: '0.58.1',
      dbUpdatedAt: '2026-07-28T06:11:53Z',
    });
  });

  it('attaches the report for the results tab', async () => {
    await invoke(new FakeRunner(writeReport));
    expect(lines.some((line) => line.includes('task.addattachment'))).toBe(true);
  });

  it('deletes the env file even when the scan fails', async () => {
    const runner = new FakeRunner();
    runner.results = [{ exitCode: 125, stdout: '', stderr: 'docker: not found', timedOut: false }];
    await expect(invoke(runner)).rejects.toThrow();
    expect(fs.readdirSync(path.join(workspace, 'temp'))).toEqual([]);
  });

  it('reports a docker failure as an infrastructure error, not as findings', async () => {
    const runner = new FakeRunner();
    runner.results = [{ exitCode: 125, stdout: '', stderr: 'Cannot connect to the Docker daemon', timedOut: false }];
    await expect(invoke(runner)).rejects.toThrow(/Docker daemon/);
  });

  it('names the timeout input when the container is killed', async () => {
    const runner = new FakeRunner();
    runner.results = [{ exitCode: 137, stdout: '', stderr: '', timedOut: true }];
    await expect(invoke(runner)).rejects.toThrow(/timeoutMinutes/);
  });

  it('removes a leftover container after a timeout', async () => {
    const runner = new FakeRunner();
    runner.results = [{ exitCode: 137, stdout: '', stderr: '', timedOut: true }];
    await expect(invoke(runner)).rejects.toThrow();
    expect(runner.calls.some((call) => call.args.join(' ').includes('rm -f trivyscan-1042-0'))).toBe(
      true,
    );
  });

  it('fails with a clear message when the runner produced no report file', async () => {
    await expect(invoke(new FakeRunner())).rejects.toThrow(/did not produce a report/);
  });
});
