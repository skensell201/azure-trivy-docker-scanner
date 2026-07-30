import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { ChildProcessRunner, ProcessResult, RunOptions } from '../../src/task/ProcessRunner';
import { Publisher } from '../../src/task/Publisher';
import { runScan } from '../../src/task/run';

/**
 * Every other test in this repository injects a fake ProcessRunner, so nothing else
 * proves that the argv DockerCommand builds is the argv that actually reaches a process.
 * This subclass routes only the "docker" command to the fake docker script, through the
 * real `ChildProcessRunner.run` (via `super.run`): the spawn, the stdout/stderr capture,
 * the timeout handling, all of it is exercised for real, not stubbed.
 */
class FakeDockerRunner extends ChildProcessRunner {
  run(command: string, args: string[], options?: RunOptions): Promise<ProcessResult> {
    const target = command === 'docker' ? path.join(__dirname, 'fake-docker.js') : command;
    return super.run(process.execPath, [target, ...args], options);
  }
}

describe('scan against a fake docker binary', () => {
  let workspace: string;
  let log: string;
  let envLog: string;
  let contextFile: string;

  beforeEach(() => {
    workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'integration-'));
    fs.mkdirSync(path.join(workspace, 'temp'), { recursive: true });
    log = path.join(workspace, 'docker-calls.log');
    envLog = path.join(workspace, 'env-file-contents.log');
    fs.writeFileSync(log, '');
    fs.writeFileSync(envLog, '');

    // fake-docker.js cannot learn the log/workspace paths through process.env: under
    // ts-jest, `process.env` mutated here lives in this test file's own vm context, but
    // ChildProcessRunner's plain `spawn(command, args, { cwd })` (no explicit `env`)
    // sources its default environment from the real outer process instead, so a spawned
    // child never observes env vars a test set (verified directly: a bare child spawned
    // with no `env` option reads back `undefined` for a variable set on `process.env`
    // immediately beforehand). A JSON "context" file on disk, keyed by this process's
    // pid -- which fake-docker.js reads back as its own `process.ppid`, a plain OS
    // integer rather than an object property Jest could sandbox -- sidesteps that
    // entirely. See the longer comment in fake-docker.js.
    contextFile = path.join(os.tmpdir(), `trivy-fake-docker-context-${process.pid}.json`);
    fs.writeFileSync(contextFile, JSON.stringify({ log, workspace, envLog }));
  });

  afterEach(() => {
    fs.rmSync(workspace, { recursive: true, force: true });
    fs.rmSync(contextFile, { force: true });
  });

  const readCalls = (): string[][] =>
    fs
      .readFileSync(log, 'utf8')
      .trim()
      .split('\n')
      .map((line) => JSON.parse(line) as string[]);

  it('runs the runner image and turns its report into a gate result', async () => {
    const lines: string[] = [];
    const result = await runScan({
      defaults: { dbRepository: 'registry.example.com/trivy-db:2', failOn: 'HIGH' },
      runners: [{ alias: 'baseline', image: 'registry.example.com/trivy:0.58.1', isDefault: true }],
      inputs: { scanType: 'image', target: 'app:1.4.2' },
      agent: {
        sourcesDir: workspace,
        agentHomeDir: workspace,
        tempDir: path.join(workspace, 'temp'),
        buildId: '1042',
      },
      scanIndex: 0,
      processRunner: new FakeDockerRunner(),
      publisher: new Publisher((line) => lines.push(line)),
      credentials: {},
    });

    expect(result.gate.outcome).toBe('failed');
    expect(result.report.findings[0].id).toBe('CVE-2024-21626');
    expect(lines.some((line) => line.includes('task.addattachment'))).toBe(true);
  });

  // Only two docker invocations happen here: the version probe and the JSON scan.
  // Nothing above requests the sarif format or an sbom, so run.ts never calls
  // emitExtraFormat -- see the dedicated extra-format test below for that path, where a
  // fixed call count would be wrong (a third invocation, the sarif run, is expected).
  it('passes the image and the mounts to docker exactly once', async () => {
    await runScan({
      defaults: { dbRepository: 'registry.example.com/trivy-db:2' },
      runners: [{ alias: 'baseline', image: 'registry.example.com/trivy:0.58.1', isDefault: true }],
      inputs: { scanType: 'image', target: 'app:1.4.2' },
      agent: {
        sourcesDir: workspace,
        agentHomeDir: workspace,
        tempDir: path.join(workspace, 'temp'),
        buildId: '1042',
      },
      scanIndex: 0,
      processRunner: new FakeDockerRunner(),
      publisher: new Publisher(() => undefined),
      credentials: {},
    });

    const calls = readCalls();

    expect(calls).toHaveLength(2);
    expect(calls[1]).toContain('registry.example.com/trivy:0.58.1');
    expect(calls[1]).toContain(`${workspace}:/workspace`);
  });

  it('leaves no env file behind', async () => {
    await runScan({
      defaults: { dbRepository: 'registry.example.com/trivy-db:2' },
      runners: [{ alias: 'baseline', image: 'registry.example.com/trivy:0.58.1', isDefault: true }],
      inputs: { scanType: 'image', target: 'app:1.4.2' },
      agent: {
        sourcesDir: workspace,
        agentHomeDir: workspace,
        tempDir: path.join(workspace, 'temp'),
        buildId: '1042',
      },
      scanIndex: 0,
      processRunner: new FakeDockerRunner(),
      publisher: new Publisher(() => undefined),
      credentials: {},
    });

    expect(fs.readdirSync(path.join(workspace, 'temp'))).toEqual([]);
  });

  // DockerCommand.test.ts already pins that buildTrivyEnv puts credentials in the env
  // map and never in argv, but that is a claim about an in-memory object. This is the
  // one place that proves it end to end: --env-file names a real file, a real process
  // reads it (see fake-docker.js), and the credentials must show up there and nowhere
  // in the argv that reached that process.
  it('carries registry credentials to the container through the env file, not through argv', async () => {
    await runScan({
      defaults: { dbRepository: 'registry.example.com/trivy-db:2' },
      runners: [{ alias: 'baseline', image: 'registry.example.com/trivy:0.58.1', isDefault: true }],
      inputs: { scanType: 'image', target: 'app:1.4.2' },
      agent: {
        sourcesDir: workspace,
        agentHomeDir: workspace,
        tempDir: path.join(workspace, 'temp'),
        buildId: '1042',
      },
      scanIndex: 0,
      processRunner: new FakeDockerRunner(),
      publisher: new Publisher(() => undefined),
      credentials: { username: 'svc-scanner', password: 'p@ss-w0rd' },
    });

    const envFileContent = fs.readFileSync(envLog, 'utf8');
    expect(envFileContent).toContain('TRIVY_USERNAME=svc-scanner');
    expect(envFileContent).toContain('TRIVY_PASSWORD=p@ss-w0rd');

    const argvLog = fs.readFileSync(log, 'utf8');
    expect(argvLog).not.toContain('p@ss-w0rd');
    expect(argvLog).not.toContain('svc-scanner');
  });

  // Exercises the extra-format path end to end: a second, real docker invocation for
  // sarif, distinct from the JSON scan, whose output the fake docker writes to its own
  // container path. run.test.ts already pins this with a fake ProcessRunner; this proves
  // the same behavior survives an actual spawn with real argv and a real file on disk.
  it('runs a second docker invocation to produce sarif when the format is requested', async () => {
    const lines: string[] = [];
    await runScan({
      defaults: { dbRepository: 'registry.example.com/trivy-db:2' },
      runners: [{ alias: 'baseline', image: 'registry.example.com/trivy:0.58.1', isDefault: true }],
      inputs: { scanType: 'image', target: 'app:1.4.2', formats: ['json', 'sarif'] },
      agent: {
        sourcesDir: workspace,
        agentHomeDir: workspace,
        tempDir: path.join(workspace, 'temp'),
        buildId: '1042',
      },
      scanIndex: 0,
      processRunner: new FakeDockerRunner(),
      publisher: new Publisher((line) => lines.push(line)),
      credentials: {},
    });

    const calls = readCalls();
    expect(calls).toHaveLength(3);
    expect(calls[2]).toContain('sarif');
    expect(calls[2]).toContain('trivyscan-1042-0-sarif');
    expect(fs.existsSync(path.join(workspace, '.trivy', 'report-0.sarif'))).toBe(true);
    expect(lines.some((line) => line.includes('CodeAnalysisLogs'))).toBe(true);
  });

  // Exercises sourceTransfer: copy end to end through a real spawn, the same way the
  // 'mount' tests above do -- this is precisely the case a fake ProcessRunner (run.test.ts)
  // cannot catch: a disagreement between the argv DockerCommand builds for `create`/`cp`/
  // `start`/`rm` and what a real process actually receives and can act on.
  describe('sourceTransfer: copy', () => {
    it('runs the create/cp/start/cp/rm sequence and turns the copied-out report into a gate result', async () => {
      const lines: string[] = [];
      const result = await runScan({
        defaults: { dbRepository: 'registry.example.com/trivy-db:2', failOn: 'HIGH' },
        runners: [{ alias: 'baseline', image: 'registry.example.com/trivy:0.58.1', isDefault: true }],
        inputs: { scanType: 'image', target: 'app:1.4.2', sourceTransfer: 'copy' },
        agent: {
          sourcesDir: workspace,
          agentHomeDir: workspace,
          tempDir: path.join(workspace, 'temp'),
          buildId: '1042',
        },
        scanIndex: 0,
        processRunner: new FakeDockerRunner(),
        publisher: new Publisher((line) => lines.push(line)),
        credentials: {},
      });

      expect(result.gate.outcome).toBe('failed');
      expect(result.report.findings[0].id).toBe('CVE-2024-21626');
      expect(lines.some((line) => line.includes('task.addattachment'))).toBe(true);

      // Two docker invocations happen before the scan container's own lifecycle: the
      // version probe (docker run ... version) and nothing else, since login is not
      // configured -- then the five-step create/cp/start/cp/rm sequence.
      const calls = readCalls();
      expect(calls).toHaveLength(6);
      expect(calls[0]).toContain('version');
      const subcommands = calls.slice(1).map((call) => call[0]);
      expect(subcommands).toEqual(['create', 'cp', 'start', 'cp', 'rm']);
    });

    it('never mounts the sources directory or the cache directory into the scan container', async () => {
      await runScan({
        defaults: { dbRepository: 'registry.example.com/trivy-db:2' },
        runners: [{ alias: 'baseline', image: 'registry.example.com/trivy:0.58.1', isDefault: true }],
        inputs: { scanType: 'image', target: 'app:1.4.2', sourceTransfer: 'copy' },
        agent: {
          sourcesDir: workspace,
          agentHomeDir: workspace,
          tempDir: path.join(workspace, 'temp'),
          buildId: '1042',
        },
        scanIndex: 0,
        processRunner: new FakeDockerRunner(),
        publisher: new Publisher(() => undefined),
        credentials: {},
      });

      const calls = readCalls();
      expect(calls.some((call) => call.includes('-v'))).toBe(false);
      expect(calls.some((call) => call.some((token) => token.includes(`${workspace}:/workspace`)))).toBe(
        false,
      );
    });

    it('reads the report from the host path after a real docker cp copies it out', async () => {
      await runScan({
        defaults: { dbRepository: 'registry.example.com/trivy-db:2' },
        runners: [{ alias: 'baseline', image: 'registry.example.com/trivy:0.58.1', isDefault: true }],
        inputs: { scanType: 'image', target: 'app:1.4.2', sourceTransfer: 'copy' },
        agent: {
          sourcesDir: workspace,
          agentHomeDir: workspace,
          tempDir: path.join(workspace, 'temp'),
          buildId: '1042',
        },
        scanIndex: 0,
        processRunner: new FakeDockerRunner(),
        publisher: new Publisher(() => undefined),
        credentials: {},
      });

      const hostReportPath = path.join(workspace, '.trivy', 'report-0.json');
      expect(fs.existsSync(hostReportPath)).toBe(true);
      const raw = JSON.parse(fs.readFileSync(hostReportPath, 'utf8'));
      expect(raw.Results[0].Vulnerabilities[0].VulnerabilityID).toBe('CVE-2024-21626');
    });

    it('runs the sarif extra format through the copy sequence too, not a mount fallback', async () => {
      const lines: string[] = [];
      await runScan({
        defaults: { dbRepository: 'registry.example.com/trivy-db:2' },
        runners: [{ alias: 'baseline', image: 'registry.example.com/trivy:0.58.1', isDefault: true }],
        inputs: {
          scanType: 'image',
          target: 'app:1.4.2',
          sourceTransfer: 'copy',
          formats: ['json', 'sarif'],
        },
        agent: {
          sourcesDir: workspace,
          agentHomeDir: workspace,
          tempDir: path.join(workspace, 'temp'),
          buildId: '1042',
        },
        scanIndex: 0,
        processRunner: new FakeDockerRunner(),
        publisher: new Publisher((line) => lines.push(line)),
        credentials: {},
      });

      const calls = readCalls();
      // version probe, then create/cp/start/cp/rm for the JSON scan, then the same five
      // steps again for the sarif run.
      expect(calls).toHaveLength(11);
      expect(calls.some((call) => call.includes('-v'))).toBe(false);
      expect(fs.existsSync(path.join(workspace, '.trivy', 'report-0.sarif'))).toBe(true);
      expect(lines.some((line) => line.includes('CodeAnalysisLogs'))).toBe(true);
    });
  });
});
