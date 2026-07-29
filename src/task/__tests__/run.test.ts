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

  constructor(private readonly onScan?: (args: string[]) => void) {}

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
    this.onScan?.(args);
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

/**
 * Stands in for a runner image that actually writes whatever `--output` it was given:
 * unlike `writeReport`, it inspects each invocation's args instead of always writing
 * report-0.json, so it works for the JSON scan and for a sarif/sbom extra run alike --
 * each one gets a file at its own container path, mapped onto the host workspace.
 */
const writeExtraOutput = (content: string) => (args: string[]) => {
  const outputIndex = args.indexOf('--output');
  if (outputIndex === -1) {
    return;
  }
  const containerPath = args[outputIndex + 1];
  const hostPath = path.join(workspace, containerPath.replace('/workspace/', ''));
  fs.mkdirSync(path.dirname(hostPath), { recursive: true });
  fs.writeFileSync(hostPath, content);
};

/**
 * Some environments (e.g. tests running as root, or certain CI filesystems) do not
 * enforce a 0o555 directory mode, so a permission-denial test would fail for a reason
 * unrelated to the code under test. Probing once up front lets the affected tests skip
 * themselves cleanly instead of failing spuriously.
 */
function permissionsAreEnforced(): boolean {
  const probeDir = fs.mkdtempSync(path.join(os.tmpdir(), 'perm-probe-'));
  fs.chmodSync(probeDir, 0o555);
  let denied = false;
  try {
    fs.mkdirSync(path.join(probeDir, 'child'));
  } catch {
    denied = true;
  }
  fs.chmodSync(probeDir, 0o755);
  fs.rmSync(probeDir, { recursive: true, force: true });
  return denied;
}

const itIfPermissionsEnforced = permissionsAreEnforced() ? it : it.skip;

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

  // The attachment above is what the results tab reads; the artifact is what a user
  // downloads from the build. They are not the same publish, and publishArtifact
  // defaults to true (ConfigResolver), so the default `invoke` helper exercises it.
  it('publishes the report as a build artifact under TrivyReports when publishArtifact is set', async () => {
    await invoke(new FakeRunner(writeReport));
    expect(lines.some((line) => line.includes('artifactname=TrivyReports'))).toBe(true);
  });

  it('does not publish the report as a build artifact when publishArtifact is cleared', async () => {
    const runner = new FakeRunner(writeReport);
    await runScan({
      defaults,
      runners,
      inputs: { ...inputs, publishArtifact: false },
      agent,
      scanIndex: 0,
      processRunner: runner,
      publisher: new Publisher((line) => lines.push(line)),
      credentials: {},
    });
    expect(lines.some((line) => line.includes('artifactname=TrivyReports'))).toBe(false);
    // The results-tab attachment is unaffected by publishArtifact: they are two
    // different mechanisms, and turning off the artifact must not turn off the tab too.
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

  // The version probe is decoration: even a process runner whose probe call rejects
  // outright (not just returns junk stdout) must not fail the scan. The report loses
  // trivyVersion/dbUpdatedAt, and a warning is emitted so a stale/unknown database is
  // still visible to whoever investigates, instead of being silently swallowed.
  it('warns and completes the scan when the version probe rejects', async () => {
    class RejectingVersionRunner implements ProcessRunner {
      run(command: string, args: string[]): Promise<ProcessResult> {
        if (args.includes('version')) {
          return Promise.reject(new Error('spawn docker ENOENT'));
        }
        writeReport();
        return Promise.resolve({ exitCode: 0, stdout: '', stderr: '', timedOut: false });
      }
    }

    const result = await invoke(new RejectingVersionRunner());

    expect(result.report.runner).toEqual({ alias: 'baseline', image: 'reg.corp/trivy:0.58.1' });
    expect(result.gate.outcome).toBe('failed');
    expect(
      lines.some(
        (line) =>
          line.includes('type=warning') && /version probe/i.test(line) && line.includes('ENOENT'),
      ),
    ).toBe(true);
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

  // The cache directory is the one directory-creation failure with somewhere for the
  // user to go: it comes from the project's Trivy settings (cacheDir), so the message
  // must point there in addition to naming the path and the underlying reason.
  itIfPermissionsEnforced(
    'names the cache directory, its path and the reason when it cannot be created',
    async () => {
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
        ).rejects.toThrow(/cache directory.*readonly-parent.*EACCES.*Trivy settings/s);
      } finally {
        fs.chmodSync(readonlyParent, 0o755);
      }
    },
  );

  // The report-output directory (sourcesDir/.trivy) has no administrator setting behind
  // it -- unlike the cache directory it is always a subdirectory of the checked-out
  // sources -- so its message names the path and the reason but does not invent a
  // setting to point at.
  itIfPermissionsEnforced(
    'names the report output directory, its path and the reason when it cannot be created',
    async () => {
      const readonlySources = path.join(workspace, 'readonly-sources');
      fs.mkdirSync(readonlySources);
      fs.chmodSync(readonlySources, 0o555);
      try {
        await expect(
          runScan({
            defaults,
            runners,
            inputs,
            agent: { ...agent, sourcesDir: readonlySources },
            scanIndex: 0,
            processRunner: new FakeRunner(writeReport),
            publisher: new Publisher((line) => lines.push(line)),
            credentials: {},
          }),
        ).rejects.toThrow(/report output directory.*readonly-sources.*EACCES/s);
      } finally {
        fs.chmodSync(readonlySources, 0o755);
      }
    },
  );

  it('runs a second container to produce sarif when the format is requested', async () => {
    const runner = new FakeRunner(writeExtraOutput(reportBody));
    await runScan({
      defaults,
      runners,
      inputs: { ...inputs, formats: ['json', 'sarif'] },
      agent,
      scanIndex: 0,
      processRunner: runner,
      publisher: new Publisher((line) => lines.push(line)),
      credentials: {},
    });
    expect(runner.calls.filter((call) => call.args.includes('sarif'))).toHaveLength(1);
    expect(lines.some((line) => line.includes('CodeAnalysisLogs'))).toBe(true);
  });

  it('runs a second container to produce an sbom when asked', async () => {
    const runner = new FakeRunner(writeExtraOutput(reportBody));
    await runScan({
      defaults,
      runners,
      inputs: { ...inputs, generateSbom: 'cyclonedx' },
      agent,
      scanIndex: 0,
      processRunner: runner,
      publisher: new Publisher((line) => lines.push(line)),
      credentials: {},
    });
    expect(runner.calls.filter((call) => call.args.includes('cyclonedx'))).toHaveLength(1);
    expect(lines.some((line) => line.includes('TrivySBOM'))).toBe(true);
  });

  it('warns but does not fail the scan when the sarif run fails', async () => {
    const runner = new FakeRunner(writeExtraOutput(reportBody));
    runner.results = [
      { exitCode: 0, stdout: '', stderr: '', timedOut: false },
      { exitCode: 1, stdout: '', stderr: 'sarif template missing', timedOut: false },
    ];
    const result = await runScan({
      defaults,
      runners,
      inputs: { ...inputs, formats: ['json', 'sarif'] },
      agent,
      scanIndex: 0,
      processRunner: runner,
      publisher: new Publisher((line) => lines.push(line)),
      credentials: {},
    });
    expect(result.gate.outcome).toBe('failed');
    expect(lines.some((line) => line.includes('type=warning'))).toBe(true);
  });

  // Self-review pin: the sarif/sbom runs must reuse the exact env file the JSON scan
  // wrote (same registry credentials, same TRIVY_* vars), and it must still be removed
  // exactly once -- not once per docker invocation, and not leaked because an extra
  // run happened after the "normal" cleanup point.
  it('reuses the same env file for an extra-format run and removes it exactly once', async () => {
    const runner = new FakeRunner(writeExtraOutput(reportBody));
    await runScan({
      defaults,
      runners,
      inputs: { ...inputs, formats: ['json', 'sarif'] },
      agent,
      scanIndex: 0,
      processRunner: runner,
      publisher: new Publisher((line) => lines.push(line)),
      credentials: {},
    });

    const envFileArgs = runner.calls
      .filter((call) => call.args.includes('--env-file'))
      .map((call) => call.args[call.args.indexOf('--env-file') + 1]);
    expect(envFileArgs).toHaveLength(2);
    expect(new Set(envFileArgs).size).toBe(1);
    expect(fs.readdirSync(path.join(workspace, 'temp'))).toEqual([]);
  });

  // Self-review pin: when both a sarif and an sbom run are requested for the same
  // scan, they must not clash with each other or with the main scan on container name
  // or output path -- three docker invocations, three distinct names.
  it('gives the scan, the sarif run and the sbom run distinct container names', async () => {
    const runner = new FakeRunner(writeExtraOutput(reportBody));
    await runScan({
      defaults,
      runners,
      inputs: { ...inputs, formats: ['json', 'sarif'], generateSbom: 'cyclonedx' },
      agent,
      scanIndex: 0,
      processRunner: runner,
      publisher: new Publisher((line) => lines.push(line)),
      credentials: {},
    });

    const names = runner.calls
      .filter((call) => call.args.includes('--name'))
      .map((call) => call.args[call.args.indexOf('--name') + 1]);
    expect(names).toEqual(
      expect.arrayContaining(['trivyscan-1042-0', 'trivyscan-1042-0-sarif', 'trivyscan-1042-0-sbom']),
    );
    expect(new Set(names).size).toBe(names.length);
  });
});
