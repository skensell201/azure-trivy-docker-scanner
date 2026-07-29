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

  // Self-review pin: envFile removal happens in a `finally` around only the docker
  // scan call, so it runs before report parsing is ever attempted. A regression that
  // moved the removal to wrap the whole function (e.g. "cleanup once at the end")
  // would still pass every other test here but would leave the env file behind when
  // parsing throws, since parseTrivyReport runs after that finally block today.
  it('deletes the env file even when the report file is not valid JSON', async () => {
    const runner = new FakeRunner(() => {
      fs.mkdirSync(path.join(workspace, '.trivy'), { recursive: true });
      fs.writeFileSync(path.join(workspace, '.trivy', 'report-0.json'), 'not json');
    });
    await expect(invoke(runner)).rejects.toThrow(/not valid JSON/);
    expect(fs.readdirSync(path.join(workspace, 'temp'))).toEqual([]);
  });

  // Self-review pin for "what if the probe returns junk": parseVersion swallows a JSON
  // parse failure and returns {}, and runScan never inspects the probe's exit code, so
  // a garbled `trivy version` response must not fail the scan -- it only means the
  // report's runner section is missing trivyVersion/dbUpdatedAt.
  it('completes the scan when the version probe returns unparsable output', async () => {
    class JunkVersionRunner implements ProcessRunner {
      run(command: string, args: string[]): Promise<ProcessResult> {
        if (args.includes('version')) {
          return Promise.resolve({ exitCode: 0, stdout: 'not json at all', stderr: '', timedOut: false });
        }
        writeReport();
        return Promise.resolve({ exitCode: 0, stdout: '', stderr: '', timedOut: false });
      }
    }

    const result = await invoke(new JunkVersionRunner());
    expect(result.report.runner).toEqual({ alias: 'baseline', image: 'reg.corp/trivy:0.58.1' });
    expect(result.report.findings).toHaveLength(1);
  });

  // Self-review pin for scanIndex: two TrivyScan steps in the same job run
  // concurrently (Promise.all, not sequentially) against the same sourcesDir and must
  // not read or overwrite each other's report file or container name.
  it('keeps two concurrent scans in the same job from colliding on report files', async () => {
    const reportA = JSON.stringify({
      ArtifactName: 'app:1.4.2',
      Results: [{ Target: 'app:1.4.2', Vulnerabilities: [{ VulnerabilityID: 'CVE-A', Severity: 'CRITICAL' }] }],
    });
    const reportB = JSON.stringify({
      ArtifactName: 'app:2.0.0',
      Results: [{ Target: 'app:2.0.0', Vulnerabilities: [{ VulnerabilityID: 'CVE-B', Severity: 'LOW' }] }],
    });

    const runnerA = new FakeRunner(() => {
      fs.mkdirSync(path.join(workspace, '.trivy'), { recursive: true });
      fs.writeFileSync(path.join(workspace, '.trivy', 'report-0.json'), reportA);
    });
    const runnerB = new FakeRunner(() => {
      fs.mkdirSync(path.join(workspace, '.trivy'), { recursive: true });
      fs.writeFileSync(path.join(workspace, '.trivy', 'report-1.json'), reportB);
    });

    const [resultA, resultB] = await Promise.all([
      runScan({
        defaults,
        runners,
        inputs,
        agent,
        scanIndex: 0,
        processRunner: runnerA,
        publisher: new Publisher((line) => lines.push(line)),
        credentials: {},
      }),
      runScan({
        defaults,
        runners,
        inputs: { ...inputs, target: 'app:2.0.0' },
        agent,
        scanIndex: 1,
        processRunner: runnerB,
        publisher: new Publisher((line) => lines.push(line)),
        credentials: {},
      }),
    ]);

    expect(resultA.reportPath).toBe(path.join(workspace, '.trivy', 'report-0.json'));
    expect(resultB.reportPath).toBe(path.join(workspace, '.trivy', 'report-1.json'));
    expect(resultA.report.findings[0].id).toBe('CVE-A');
    expect(resultB.report.findings[0].id).toBe('CVE-B');
  });

  // Self-review pin for "what if the cache directory cannot be created": mkdirSync's
  // own error is allowed to propagate unwrapped. This pins that Node's raw EACCES
  // error still names the exact path in its message, so the build log is not left
  // pointing at nothing -- but see the report for why this is weaker than the
  // guidance-carrying messages the rest of this module gives on other failure paths.
  it('names the path when the cache directory cannot be created', async () => {
    const readonlyParent = path.join(workspace, 'readonly-parent');
    fs.mkdirSync(readonlyParent);
    fs.chmodSync(readonlyParent, 0o555);
    try {
      await expect(
        runScan({
          defaults,
          runners,
          inputs,
          agent: { ...agent, agentHomeDir: readonlyParent },
          scanIndex: 0,
          processRunner: new FakeRunner(writeReport),
          publisher: new Publisher((line) => lines.push(line)),
          credentials: {},
        }),
      ).rejects.toThrow(/readonly-parent/);
    } finally {
      fs.chmodSync(readonlyParent, 0o755);
    }
  });
});
