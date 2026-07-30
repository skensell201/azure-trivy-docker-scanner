import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { runScan } from '../run';
import { ProcessResult, ProcessRunner, RunOptions } from '../ProcessRunner';
import { Publisher } from '../Publisher';
import { AgentContext, DatabaseConfig, DefaultsConfig, RunnerConfig, TaskInputs } from '../../shared/types';

class FakeRunner implements ProcessRunner {
  calls: { command: string; args: string[]; options?: RunOptions }[] = [];
  results: ProcessResult[] = [];
  /** Consumed by a `docker login` call only; defaults to success so most tests need not set it. */
  loginResults: ProcessResult[] = [];

  constructor(private readonly onScan?: (args: string[]) => void) {}

  run(command: string, args: string[], options?: RunOptions): Promise<ProcessResult> {
    this.calls.push({ command, args, options });
    if (args.includes('login')) {
      return Promise.resolve(
        this.loginResults.shift() ?? { exitCode: 0, stdout: '', stderr: '', timedOut: false },
      );
    }
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

// The runner names a catalogued database (the current, non-deprecated model), so the bulk of
// this suite -- which is about docker exit codes, timeouts, extra formats, JUnit output, and
// so on, not about database resolution -- never takes the deprecated dbRepository fallback and
// never emits the fallback warning. The dedicated "database credentials" and "deprecated
// database fallback" describe blocks below are what exercise the fallback path itself.
const databases: DatabaseConfig[] = [
  { alias: 'default-db', repository: 'registry.example.com/trivy-db:2' },
];
const runners: RunnerConfig[] = [
  {
    alias: 'baseline',
    image: 'registry.example.com/trivy:0.58.1',
    isDefault: true,
    enabled: true,
    database: 'default-db',
  },
];
const defaults: DefaultsConfig = {};
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
    databases,
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

  /**
   * Extracts the host path a `##vso[task.addattachment ...]` / `##vso[artifact.upload ...]`
   * line points at, so tests can read back and assert on the actual file content instead
   * of only asserting the logging command was emitted at all.
   */
  const attachedPath = (predicate: (line: string) => boolean): string => {
    const line = lines.find(predicate);
    if (line === undefined) {
      throw new Error('expected line not found');
    }
    return line.slice(line.indexOf(']') + 1);
  };

  // This is the crux of fix 1: the attachment must carry the *normalized* report (the
  // one with schemaVersion, artifactName, kindCounts and each finding's kind), not the
  // raw trivy JSON that report-0.json already is. Without this, everything the parser
  // computes is thrown away and the results tab has nothing to read.
  it('attaches the normalized report, not the raw trivy JSON', async () => {
    await invoke(new FakeRunner(writeReport));
    const hostPath = attachedPath((line) => line.includes('task.addattachment'));

    expect(hostPath).not.toBe(path.join(workspace, '.trivy', 'report-0.json'));
    const attached = JSON.parse(fs.readFileSync(hostPath, 'utf8'));
    expect(attached).toMatchObject({
      schemaVersion: 1,
      artifactName: 'app:1.4.2',
    });
    expect(attached.findings[0]).toMatchObject({ kind: 'vulnerability', id: 'CVE-1' });
    expect(attached.kindCounts).toBeDefined();
  });

  it('carries the runner alias, trivy version and database date in the attached report', async () => {
    await invoke(new FakeRunner(writeReport));
    const hostPath = attachedPath((line) => line.includes('task.addattachment'));
    const attached = JSON.parse(fs.readFileSync(hostPath, 'utf8'));

    expect(attached.runner).toMatchObject({
      alias: 'baseline',
      trivyVersion: '0.58.1',
      dbUpdatedAt: '2026-07-28T06:11:53Z',
    });
  });

  // The in-memory NormalizedReport already neutralizes control characters in trivy-reported
  // text (ReportParser.sanitizeFinding); this pins that the *attached file* carries that same
  // neutralized text rather than whatever trivy wrote raw to report-0.json, which was exactly
  // the bug: the sanitized model was computed and then thrown away in favor of the raw file.
  it('neutralizes a hostile finding title in the attached content, not merely in memory', async () => {
    const hostileTitle = 'escape\n##vso[task.complete result=Succeeded]';
    const runner = new FakeRunner(() => {
      fs.mkdirSync(path.join(workspace, '.trivy'), { recursive: true });
      fs.writeFileSync(
        path.join(workspace, '.trivy', 'report-0.json'),
        JSON.stringify({
          ArtifactName: 'app:1.4.2',
          Results: [
            {
              Target: 'app:1.4.2',
              Vulnerabilities: [
                { VulnerabilityID: 'CVE-9', PkgName: 'foo', Severity: 'CRITICAL', Title: hostileTitle },
              ],
            },
          ],
        }),
      );
    });

    await invoke(runner);

    const hostPath = attachedPath((line) => line.includes('task.addattachment'));
    const attached = JSON.parse(fs.readFileSync(hostPath, 'utf8'));
    expect(attached.findings[0].title).toBe('escape ##vso[task.complete result=Succeeded]');
    expect(attached.findings[0].title).not.toMatch(/[\n\r]/);
    expect(attached.findings[0].title).not.toBe(hostileTitle);
  });

  // The attachment above is what the results tab reads; the artifact is what a user
  // downloads from the build. They are not the same publish, and publishArtifact
  // defaults to true (ConfigResolver), so the default `invoke` helper exercises it.
  it('publishes the report as a build artifact under TrivyReports when publishArtifact is set', async () => {
    await invoke(new FakeRunner(writeReport));
    expect(lines.some((line) => line.includes('artifactname=TrivyReports'))).toBe(true);
  });

  // A user downloading build results wants trivy's own output (that is what "TrivyReports"
  // has always meant); only the results-tab attachment above switches to the normalized shape.
  it('publishes the raw trivy JSON, not the normalized report, as the TrivyReports artifact', async () => {
    await invoke(new FakeRunner(writeReport));
    const hostPath = attachedPath((line) => line.includes('artifactname=TrivyReports'));

    expect(hostPath).toBe(path.join(workspace, '.trivy', 'report-0.json'));
    const raw = JSON.parse(fs.readFileSync(hostPath, 'utf8'));
    expect(raw.SchemaVersion).toBe(2);
    expect(raw.schemaVersion).toBeUndefined();
  });

  // Self-review pin: the attachment is the contract the results-tab plan depends on, so a
  // failure writing it must fail the scan loudly rather than silently publishing nothing
  // (or worse, an empty/stale file) while the build goes green.
  itIfPermissionsEnforced(
    'fails the scan loudly when the normalized report cannot be written',
    async () => {
      const trivyDir = path.join(workspace, '.trivy');
      const runner = new FakeRunner(() => {
        writeReport();
        fs.chmodSync(trivyDir, 0o555);
      });
      try {
        await expect(invoke(runner)).rejects.toThrow(/normalized report/i);
      } finally {
        fs.chmodSync(trivyDir, 0o755);
      }
    },
  );

  it('does not publish the report as a build artifact when publishArtifact is cleared', async () => {
    const runner = new FakeRunner(writeReport);
    await runScan({
      defaults,
      runners,
      databases,
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

  describe('publishTestResults', () => {
    it('does not publish JUnit test results by default', async () => {
      await invoke(new FakeRunner(writeReport));
      expect(lines.some((line) => line.includes('results.publish'))).toBe(false);
    });

    it('publishes JUnit test results when enabled, and the published path is the file that was written', async () => {
      const runner = new FakeRunner(writeReport);
      await runScan({
        defaults,
        runners,
        databases,
        inputs: { ...inputs, publishTestResults: true },
        agent,
        scanIndex: 0,
        processRunner: runner,
        publisher: new Publisher((line) => lines.push(line)),
        credentials: {},
      });

      const line = lines.find((l) => l.includes('results.publish'));
      expect(line).toBeDefined();
      expect(line).toContain('type=JUnit;mergeResults=false;runTitle=Trivy - app:1.4.2;');

      const hostPath = attachedPath((l) => l.includes('results.publish'));
      expect(fs.existsSync(hostPath)).toBe(true);
      const xml = fs.readFileSync(hostPath, 'utf8');
      expect(xml).toContain('<testsuite');
      expect(xml).toContain('CVE-1');
    });

    it('does not publish JUnit test results when explicitly disabled', async () => {
      const runner = new FakeRunner(writeReport);
      await runScan({
        defaults,
        runners,
        databases,
        inputs: { ...inputs, publishTestResults: false },
        agent,
        scanIndex: 0,
        processRunner: runner,
        publisher: new Publisher((line) => lines.push(line)),
        credentials: {},
      });
      expect(lines.some((line) => line.includes('results.publish'))).toBe(false);
    });

    /**
     * Pulls one attribute off the `<testsuite ...>` opening tag by name, without a full XML
     * parser: run.test.ts has no jsdom/DOMParser dependency the way JUnitReport.test.ts does
     * (that file owns the well-formedness assertions), so this stays a plain regex, good enough
     * to pin which value run.ts chose to pass through into the file it wrote.
     */
    const testsuiteAttr = (xml: string, name: string): string | undefined =>
      xml.match(new RegExp(`<testsuite[^>]*\\s${name}="([^"]*)"`))?.[1];

    // This is the crux of the duration fix: real wall-clock time in a test cannot be pinned to
    // an exact value without a fake-timer dependency this suite deliberately avoids (see the
    // task notes this pins), so "a valid, non-negative number" is the honest, deterministic
    // thing to assert -- it is what tells apart the actual measurement this change adds from the
    // hardcoded `time="0"` the defect report was filed against.
    it('publishes a non-negative, numeric duration on the testsuite element', async () => {
      const runner = new FakeRunner(writeReport);
      await runScan({
        defaults,
        runners,
        databases,
        inputs: { ...inputs, publishTestResults: true },
        agent,
        scanIndex: 0,
        processRunner: runner,
        publisher: new Publisher((line) => lines.push(line)),
        credentials: {},
      });

      const hostPath = attachedPath((l) => l.includes('results.publish'));
      const xml = fs.readFileSync(hostPath, 'utf8');
      const time = Number(testsuiteAttr(xml, 'time'));

      expect(Number.isNaN(time)).toBe(false);
      expect(time).toBeGreaterThanOrEqual(0);
    });

    // Falls back to when the scan started (a real Date, ISO-formatted) only because this
    // fixture's report carries no CreatedAt of its own -- see the next test for the case where
    // trivy does provide one.
    it('falls back to a valid ISO timestamp for the testsuite when trivy reports no createdAt', async () => {
      const runner = new FakeRunner(writeReport);
      await runScan({
        defaults,
        runners,
        databases,
        inputs: { ...inputs, publishTestResults: true },
        agent,
        scanIndex: 0,
        processRunner: runner,
        publisher: new Publisher((line) => lines.push(line)),
        credentials: {},
      });

      const hostPath = attachedPath((l) => l.includes('results.publish'));
      const xml = fs.readFileSync(hostPath, 'utf8');
      const timestamp = testsuiteAttr(xml, 'timestamp');

      expect(timestamp).toBeDefined();
      expect(Number.isNaN(new Date(timestamp as string).getTime())).toBe(false);
    });

    // The crux of the timestamp fix: trivy's own report.createdAt, when present, is closer to
    // the truth than this task's own before/after bracket around the docker invocation, so it
    // must win over the measured scan-start time.
    it("uses trivy's own createdAt as the testsuite timestamp when the report carries one", async () => {
      const runner = new FakeRunner(() => {
        fs.mkdirSync(path.join(workspace, '.trivy'), { recursive: true });
        fs.writeFileSync(
          path.join(workspace, '.trivy', 'report-0.json'),
          JSON.stringify({
            SchemaVersion: 2,
            CreatedAt: '2026-01-02T03:04:05Z',
            ArtifactName: 'app:1.4.2',
            Results: [
              {
                Target: 'app:1.4.2',
                Vulnerabilities: [
                  { VulnerabilityID: 'CVE-1', PkgName: 'runc', Severity: 'CRITICAL', Title: 'escape' },
                ],
              },
            ],
          }),
        );
      });
      await runScan({
        defaults,
        runners,
        databases,
        inputs: { ...inputs, publishTestResults: true },
        agent,
        scanIndex: 0,
        processRunner: runner,
        publisher: new Publisher((line) => lines.push(line)),
        credentials: {},
      });

      const hostPath = attachedPath((l) => l.includes('results.publish'));
      const xml = fs.readFileSync(hostPath, 'utf8');
      expect(testsuiteAttr(xml, 'timestamp')).toBe('2026-01-02T03:04:05Z');
    });
  });

  it('deletes the env file even when the scan fails', async () => {
    const runner = new FakeRunner();
    runner.results = [{ exitCode: 125, stdout: '', stderr: 'docker: not found', timedOut: false }];
    await expect(invoke(runner)).rejects.toThrow();
    expect(fs.readdirSync(path.join(workspace, 'temp'))).toEqual([]);
  });

  // EnvFile.removeEnvFile never throws (a delete failure must not replace the real scan
  // outcome), so a failed removal is only visible if run.ts wires its onWarning callback
  // through to the publisher. Without that wiring this failure is completely silent and
  // the registry credentials file is left behind with nobody told.
  itIfPermissionsEnforced(
    'warns naming the env file when it cannot be removed, without affecting the scan result',
    async () => {
      const runner = new FakeRunner(() => {
        // The env file already exists by the time the scan process runs (writeEnvFile
        // ran before this call). Denying write on its containing directory makes the
        // unlink inside removeEnvFile fail with EACCES once the `finally` runs.
        fs.chmodSync(agent.tempDir, 0o555);
        writeReport();
      });
      try {
        const result = await invoke(runner);
        expect(result.gate.outcome).toBe('failed');
        expect(
          lines.some(
            (line) =>
              line.includes('type=warning') &&
              line.includes('trivy-scan-0.env') &&
              /failed to remove|could not remove/i.test(line),
          ),
        ).toBe(true);
      } finally {
        fs.chmodSync(agent.tempDir, 0o755);
      }
    },
  );

  it('reports a docker failure as an infrastructure error, not as findings', async () => {
    const runner = new FakeRunner();
    runner.results = [{ exitCode: 125, stdout: '', stderr: 'Cannot connect to the Docker daemon', timedOut: false }];
    await expect(invoke(runner)).rejects.toThrow(/Docker daemon/);
  });

  // Docker missing from the agent's PATH is the most likely first-run failure for this
  // task's audience. ChildProcessRunner's own doc comment says it uses exit code 127 as a
  // sentinel for *every* spawn failure (ENOENT, EACCES, ...), so 127 alone cannot tell
  // "docker is missing" apart from some other spawn problem -- only the ENOENT-shaped
  // stderr node attaches for that specific case makes it a reliable signal.
  it('explains that the agent has no docker on its PATH when the scan exits 127 with an ENOENT-shaped stderr', async () => {
    const runner = new FakeRunner();
    runner.results = [{ exitCode: 127, stdout: '', stderr: 'spawn docker ENOENT', timedOut: false }];
    let error: Error | undefined;
    try {
      await invoke(runner);
    } catch (e) {
      error = e as Error;
    }
    expect(error?.message).toMatch(/docker/i);
    expect(error?.message).toMatch(/PATH/);
    expect(error?.message).toMatch(/cannot fall back/i);
  });

  // Fall-through: a bare 127 whose stderr does not carry the ENOENT shape must not be
  // mislabelled as "docker is missing" -- it falls through to the ordinary infrastructure
  // message instead, the same way the db-download check below falls through.
  it('does not mislabel a 127 exit without an ENOENT-shaped stderr as docker being unavailable', async () => {
    const runner = new FakeRunner();
    runner.results = [{ exitCode: 127, stdout: '', stderr: 'permission denied', timedOut: false }];
    await expect(invoke(runner)).rejects.toThrow(/infrastructure failure/i);
  });

  // The spec requires naming dbRepository and whether credentials were supplied. Matching
  // on "failed to download vulnerability DB" rather than a full sentence: that substring has
  // stayed stable across trivy releases even as the surrounding wording (init error vs DB
  // error, OCI artifact vs OCI repository) has changed.
  it('names the dbRepository and notes credentials were supplied when the vulnerability database could not be downloaded', async () => {
    const runner = new FakeRunner();
    runner.results = [
      {
        exitCode: 1,
        stdout: '',
        stderr: 'FATAL	Fatal error	 run error: db error: failed to download vulnerability DB: OCI repository error',
        timedOut: false,
      },
    ];
    let error: Error | undefined;
    try {
      await runScan({
        defaults,
        runners,
        databases,
        inputs,
        agent,
        scanIndex: 0,
        processRunner: runner,
        publisher: new Publisher((line) => lines.push(line)),
        credentials: { username: 'svc', password: 'secret' },
      });
    } catch (e) {
      error = e as Error;
    }
    expect(error?.message).toMatch(/registry\.example\.com\/trivy-db:2/);
    expect(error?.message).toMatch(/credentials were supplied/i);
  });

  it('notes that no credentials were supplied when the vulnerability database could not be downloaded without any', async () => {
    const runner = new FakeRunner();
    runner.results = [
      { exitCode: 1, stdout: '', stderr: 'init error: DB error: failed to download vulnerability DB', timedOut: false },
    ];
    let error: Error | undefined;
    try {
      await invoke(runner);
    } catch (e) {
      error = e as Error;
    }
    expect(error?.message).toMatch(/registry\.example\.com\/trivy-db:2/);
    expect(error?.message).toMatch(/no credentials were supplied/i);
  });

  // Fall-through: an unrelated non-zero exit that does not clearly indicate a database
  // failure must not be mislabelled as one -- it falls through to the ordinary
  // infrastructure message instead of guessing.
  it('falls back to the generic infrastructure message when a non-zero exit does not clearly indicate a database failure', async () => {
    const runner = new FakeRunner();
    runner.results = [{ exitCode: 1, stdout: '', stderr: 'panic: some unrelated trivy crash', timedOut: false }];
    await expect(invoke(runner)).rejects.toThrow(/infrastructure failure/i);
  });

  // Real-installation finding: the agent itself runs in a container (e.g. a Kubernetes pod)
  // with the docker daemon in a sidecar or reached through a mounted host socket. `docker run
  // -v <sourcesDir>:/workspace` is resolved by the *daemon*, not by this task, so when the
  // daemon lives in a different mount namespace it cannot see the agent's sourcesDir and
  // silently substitutes an empty directory instead of failing the mount outright. Trivy then
  // scans zero files and cannot even write its own report there, surfacing as an opaque
  // "docker exited with code 1 ... infrastructure failure" that gives no hint the real
  // problem is the daemon's view of the filesystem, not trivy or the report path.
  it('explains that the docker daemon could not see the sources directory when trivy could not create the report at the container path', async () => {
    const runner = new FakeRunner();
    runner.results = [
      {
        exitCode: 1,
        stdout: 'INFO  Number of language-specific files  num=0',
        stderr:
          'FATAL run error: report error: unable to write results: failed to create a file: ' +
          'failed to create output file: open /workspace/.trivy/report-0.json: no such file or directory',
        timedOut: false,
      },
    ];
    let error: Error | undefined;
    try {
      await invoke(runner);
    } catch (e) {
      error = e as Error;
    }
    expect(error?.message).toMatch(/docker daemon/i);
    expect(error?.message).toContain(workspace);
    expect(error?.message).toMatch(/mount namespace/i);
    expect(error?.message).toMatch(/mountPath|mounted/i);
  });

  // Fall-through: a non-zero exit whose output happens to mention the container report path
  // (or "no such file or directory") must not be mislabelled as the daemon-mismatch case when
  // the report file was actually produced -- e.g. a later step in the same container failing
  // after trivy already wrote its report successfully. Guessing wrong here would send someone
  // chasing a daemon mount problem that does not exist.
  it('does not mislabel a non-zero exit as a daemon mount mismatch when the report file was actually written', async () => {
    const runner = new FakeRunner(() => {
      writeReport();
    });
    runner.results = [
      {
        exitCode: 1,
        stdout: '',
        stderr:
          'some later step failed referencing /workspace/.trivy/report-0.json: no such file or directory',
        timedOut: false,
      },
    ];
    await expect(invoke(runner)).rejects.toThrow(/infrastructure failure/i);
  });

  // Fall-through: an unrelated non-zero exit with a missing report file, but whose output does
  // not mention the container report path at all, must still fall back to the generic message
  // rather than being guessed as the daemon mismatch case.
  it('does not mislabel a missing report as a daemon mount mismatch when the output does not mention the container report path', async () => {
    const runner = new FakeRunner();
    runner.results = [
      { exitCode: 1, stdout: '', stderr: 'panic: some unrelated trivy crash', timedOut: false },
    ];
    await expect(invoke(runner)).rejects.toThrow(/infrastructure failure/i);
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
    expect(result.report.runner).toEqual({ alias: 'baseline', image: 'registry.example.com/trivy:0.58.1' });
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

    expect(result.report.runner).toEqual({ alias: 'baseline', image: 'registry.example.com/trivy:0.58.1' });
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
        databases,
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
        databases,
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

  // Fix 4: the version probe bind-mounts cacheDir (buildVersionArgs), so if the probe ran
  // before the directory existed, docker itself would create it on a first run -- as root,
  // and before the careful "an administrator can change it" guidance ever gets a chance to
  // fire. The cache directory must exist by the time the probe call is made.
  it('creates the cache directory before probing the runner version', async () => {
    let cacheDirExistedDuringProbe: boolean | undefined;
    class ProbeOrderRunner implements ProcessRunner {
      run(command: string, args: string[]): Promise<ProcessResult> {
        if (args.includes('version')) {
          cacheDirExistedDuringProbe = fs.existsSync(path.join(workspace, '_trivy-cache'));
          return Promise.resolve({
            exitCode: 0,
            stdout: '{"Version":"0.58.1","VulnerabilityDB":{"UpdatedAt":"2026-07-28T06:11:53Z"}}',
            stderr: '',
            timedOut: false,
          });
        }
        writeReport();
        return Promise.resolve({ exitCode: 0, stdout: '', stderr: '', timedOut: false });
      }
    }

    await invoke(new ProbeOrderRunner());
    expect(cacheDirExistedDuringProbe).toBe(true);
  });

  // The cache directory is the one directory-creation failure with somewhere for the
  // user to go: it comes from the collection's Trivy settings (cacheDir), so the message
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
            databases,
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
            databases,
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

  // ReportParser degrades an unrecognized severity label to UNKNOWN rather than
  // throwing, since trivy's output is not our data format and one strange label is no
  // reason to discard an otherwise-good scan. But UNKNOWN ranks lowest and FailOn
  // excludes it as a threshold, so a finding degraded this way can never fail the gate --
  // if a future trivy release renames a severity, the gate would go green silently
  // unless this is surfaced.
  it('warns when the report contains an unrecognized severity label', async () => {
    const runner = new FakeRunner(() => {
      fs.mkdirSync(path.join(workspace, '.trivy'), { recursive: true });
      fs.writeFileSync(
        path.join(workspace, '.trivy', 'report-0.json'),
        JSON.stringify({
          ArtifactName: 'app:1.4.2',
          Results: [
            {
              Target: 'app:1.4.2',
              Vulnerabilities: [
                { VulnerabilityID: 'CVE-9', PkgName: 'foo', Severity: 'SUPER_CRITICAL', Title: 'x' },
              ],
            },
          ],
        }),
      );
    });

    await invoke(runner);

    expect(
      lines.some(
        (line) =>
          line.includes('type=warning') &&
          line.includes('SUPER_CRITICAL') &&
          /unrecognized/i.test(line) &&
          /UNKNOWN/.test(line) &&
          /cannot fail the gate|gate/i.test(line),
      ),
    ).toBe(true);
  });

  it('does not warn about unrecognized severities when every label is known', async () => {
    await invoke(new FakeRunner(writeReport));
    expect(lines.some((line) => /unrecognized/i.test(line))).toBe(false);
  });

  it('runs a second container to produce sarif when the format is requested', async () => {
    const runner = new FakeRunner(writeExtraOutput(reportBody));
    await runScan({
      defaults,
      runners,
      databases,
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
      databases,
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
      databases,
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
      databases,
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
      databases,
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

  describe('docker login for the runner image', () => {
    const runnersWithCreds: RunnerConfig[] = [
      {
        alias: 'baseline',
        image: 'registry.example.com/trivy:0.58.1',
        isDefault: true,
        enabled: true,
        registryUsername: 'svc-runner',
        registryPassword: 'runner-p@ss',
        database: 'default-db',
      },
    ];

    it('does not attempt a docker login when the runner carries no credentials', async () => {
      const runner = new FakeRunner(writeReport);
      await invoke(runner);
      expect(runner.calls.some((call) => call.args.includes('login'))).toBe(false);
    });

    it('logs in to the runner registry, via stdin, before probing the version', async () => {
      const runner = new FakeRunner(writeReport);
      await runScan({
        defaults,
        runners: runnersWithCreds,
        databases,
        inputs,
        agent,
        scanIndex: 0,
        processRunner: runner,
        publisher: new Publisher((line) => lines.push(line)),
        credentials: {},
      });

      expect(runner.calls[0].args).toEqual([
        'login',
        'registry.example.com',
        '--username',
        'svc-runner',
        '--password-stdin',
      ]);
      expect(runner.calls[0].options?.stdin).toBe('runner-p@ss');
      expect(runner.calls[0].args.join(' ')).not.toContain('runner-p@ss');
      expect(runner.calls[1].args).toContain('version');
      expect(runner.calls[2].args).toContain('image');
    });

    it('derives the login host from a registry with a dot in its hostname', async () => {
      const runner = new FakeRunner(writeReport);
      await runScan({
        defaults,
        runners: runnersWithCreds,
        databases,
        inputs,
        agent,
        scanIndex: 0,
        processRunner: runner,
        publisher: new Publisher((line) => lines.push(line)),
        credentials: {},
      });
      expect(runner.calls[0].args[1]).toBe('registry.example.com');
    });

    it('derives the login host from a registry with an explicit port', async () => {
      const runner = new FakeRunner(writeReport);
      await runScan({
        defaults,
        runners: [
          { ...runnersWithCreds[0], image: 'registry.example.com:5000/trivy:0.58.1' },
        ],
        databases,
        inputs,
        agent,
        scanIndex: 0,
        processRunner: runner,
        publisher: new Publisher((line) => lines.push(line)),
        credentials: {},
      });
      expect(runner.calls[0].args[1]).toBe('registry.example.com:5000');
    });

    it('derives the Docker Hub host for a bare image name', async () => {
      const runner = new FakeRunner(writeReport);
      await runScan({
        defaults,
        runners: [{ ...runnersWithCreds[0], image: 'nginx:1.25' }], databases,
        inputs,
        agent,
        scanIndex: 0,
        processRunner: runner,
        publisher: new Publisher((line) => lines.push(line)),
        credentials: {},
      });
      expect(runner.calls[0].args[1]).toBe('docker.io');
    });

    // A real installation disproved the old premise: the registry can permit anonymous
    // pulls while still rejecting `docker login` for an unrelated reason (e.g. a Nexus
    // instance that has not enabled its Docker Bearer Token Realm, so login can never
    // succeed there regardless of credentials). Aborting the whole scan over a failed
    // login therefore refused work that would have succeeded. A failed login is now a
    // warning, not a fatal error: the version probe and the scan still run exactly as if
    // no credentials had been configured, and if the pull genuinely cannot happen, the
    // scan's own docker failure reports that (see the docker-exit-code tests above).
    it('warns naming the host and the runner alias when the login fails, but still probes the version and runs the scan', async () => {
      const runner = new FakeRunner(writeReport);
      runner.loginResults = [
        { exitCode: 1, stdout: '', stderr: 'unauthorized: authentication required', timedOut: false },
      ];

      const result = await runScan({
        defaults,
        runners: runnersWithCreds,
        databases,
        inputs,
        agent,
        scanIndex: 0,
        processRunner: runner,
        publisher: new Publisher((line) => lines.push(line)),
        credentials: {},
      });

      expect(runner.calls[0].args).toContain('login');
      expect(runner.calls.some((call) => call.args.includes('version'))).toBe(true);
      expect(runner.calls.some((call) => call.args.includes('image'))).toBe(true);
      expect(result.gate.outcome).toBe('failed');

      expect(
        lines.some(
          (line) =>
            line.includes('type=warning') &&
            line.includes('registry.example.com') &&
            line.includes('baseline') &&
            /unauthorized/i.test(line),
        ),
      ).toBe(true);
    });

    // Pins the ordering for the success path specifically (as opposed to the general
    // "logs in ... before probing the version" test above, which already covers this):
    // a successful login must still happen, and still happen first, so a private
    // registry that does require auth keeps working exactly as before.
    it('still logs in before the version probe when the login succeeds', async () => {
      const runner = new FakeRunner(writeReport);
      runner.loginResults = [{ exitCode: 0, stdout: '', stderr: '', timedOut: false }];

      await runScan({
        defaults,
        runners: runnersWithCreds,
        databases,
        inputs,
        agent,
        scanIndex: 0,
        processRunner: runner,
        publisher: new Publisher((line) => lines.push(line)),
        credentials: {},
      });

      expect(runner.calls[0].args).toContain('login');
      expect(runner.calls[1].args).toContain('version');
      expect(runner.calls[2].args).toContain('image');
      expect(lines.some((line) => line.includes('type=warning'))).toBe(false);
    });
  });

  describe('database credentials vs. target-image credentials (TRIVY_USERNAME/TRIVY_PASSWORD collision)', () => {
    const captureEnvFile = (sink: { content: string }) => (args: string[]) => {
      const envIndex = args.indexOf('--env-file');
      if (envIndex !== -1) {
        sink.content = fs.readFileSync(args[envIndex + 1], 'utf8');
      }
      writeReport();
    };

    // The catalogued database (the current, non-deprecated model) carries its own
    // credentials, resolved by ConfigResolver onto `dbRegistryUsername`/`dbRegistryPassword`.
    const databasesWithCreds: DatabaseConfig[] = [
      {
        alias: 'default-db',
        repository: 'registry.example.com/trivy-db:2',
        registryUsername: 'db-svc',
        registryPassword: 'db-p@ss',
      },
    ];

    it('uses the database credentials when no target-image credentials were supplied', async () => {
      const sink = { content: '' };
      const runner = new FakeRunner(captureEnvFile(sink));
      await runScan({
        defaults,
        runners,
        databases: databasesWithCreds,
        inputs,
        agent,
        scanIndex: 0,
        processRunner: runner,
        publisher: new Publisher((line) => lines.push(line)),
        credentials: {},
      });
      expect(sink.content).toContain('TRIVY_USERNAME=db-svc');
      expect(sink.content).toContain('TRIVY_PASSWORD=db-p@ss');
      // The TRIVY_* environment also carries the resolved database's repository, regardless
      // of where its credentials came from.
      expect(sink.content).toContain('TRIVY_DB_REPOSITORY=registry.example.com/trivy-db:2');
      expect(lines.some((line) => line.includes('type=warning'))).toBe(false);
    });

    it('prefers target-image credentials over database credentials and warns about the collision', async () => {
      const sink = { content: '' };
      const runner = new FakeRunner(captureEnvFile(sink));
      await runScan({
        defaults,
        runners,
        databases: databasesWithCreds,
        inputs,
        agent,
        scanIndex: 0,
        processRunner: runner,
        publisher: new Publisher((line) => lines.push(line)),
        credentials: { username: 'target-svc', password: 'target-p@ss' },
      });
      expect(sink.content).toContain('TRIVY_USERNAME=target-svc');
      expect(sink.content).toContain('TRIVY_PASSWORD=target-p@ss');
      expect(sink.content).not.toContain('db-svc');
      expect(sink.content).not.toContain('db-p@ss');
      expect(
        lines.some(
          (line) =>
            line.includes('type=warning') && /database/i.test(line) && /target/i.test(line),
        ),
      ).toBe(true);
    });

    it('does not warn when only target-image credentials are supplied and no database credentials exist', async () => {
      const runner = new FakeRunner(writeReport);
      await runScan({
        defaults,
        runners,
        databases,
        inputs,
        agent,
        scanIndex: 0,
        processRunner: runner,
        publisher: new Publisher((line) => lines.push(line)),
        credentials: { username: 'target-svc', password: 'target-p@ss' },
      });
      expect(lines.some((line) => line.includes('type=warning'))).toBe(false);
    });

    // Backward-compat: a runner written before the catalogue existed (no `database` set)
    // still gets its credentials from the deprecated dbRegistryUsername/dbRegistryPassword
    // defaults, and the collision rule still holds for that path too.
    it('falls back to the deprecated dbRegistryUsername/dbRegistryPassword credentials when the runner has no database', async () => {
      const sink = { content: '' };
      const runner = new FakeRunner(captureEnvFile(sink));
      const runnerWithNoDatabase: RunnerConfig[] = [
        { alias: 'legacy-runner', image: 'registry.example.com/trivy:0.58.1', isDefault: true, enabled: true },
      ];
      await runScan({
        defaults: {
          dbRepository: 'registry.example.com/trivy-db:2',
          dbRegistryUsername: 'db-svc',
          dbRegistryPassword: 'db-p@ss',
        },
        runners: runnerWithNoDatabase,
        databases: [],
        inputs,
        agent,
        scanIndex: 0,
        processRunner: runner,
        publisher: new Publisher((line) => lines.push(line)),
        credentials: {},
      });
      expect(sink.content).toContain('TRIVY_USERNAME=db-svc');
      expect(sink.content).toContain('TRIVY_PASSWORD=db-p@ss');
    });
  });

  describe('deprecated database fallback warning', () => {
    const runnerWithNoDatabase: RunnerConfig[] = [
      { alias: 'legacy-runner', image: 'registry.example.com/trivy:0.58.1', isDefault: true, enabled: true },
    ];

    it('warns exactly once, naming the runner, when the runner has no database and defaults falls back', async () => {
      const runner = new FakeRunner(writeReport);
      await runScan({
        defaults: { dbRepository: 'registry.example.com/trivy-db:2' },
        runners: runnerWithNoDatabase,
        databases: [],
        inputs,
        agent,
        scanIndex: 0,
        processRunner: runner,
        publisher: new Publisher((line) => lines.push(line)),
        credentials: {},
      });

      const deprecationWarnings = lines.filter(
        (line) => line.includes('type=warning') && /deprecated/i.test(line) && line.includes('legacy-runner'),
      );
      expect(deprecationWarnings).toHaveLength(1);
    });

    it('does not warn about the deprecated fallback when the runner names a catalogued database', async () => {
      await invoke(new FakeRunner(writeReport));
      expect(lines.some((line) => line.includes('type=warning') && /deprecated/i.test(line))).toBe(false);
    });
  });

  describe('sourceTransfer: copy', () => {
    /** Simulates `docker cp <name>:<containerPath> <hostPath>` (the "copy out" step) by
     * writing straight to the host destination the moment it is invoked -- this fake
     * runner has no real per-container filesystem, so it stands in for "trivy already
     * wrote the report inside the container" the same way `writeReport` stands in for a
     * real runner image in mount mode. A plain `cp <sourcesDir> name:/workspace` (copy
     * in) has no ':' in its *first* argument, so it is left alone. */
    const writeReportOnCopyOut = (content: string) => (args: string[]) => {
      if (args[0] === 'cp' && args[1].includes(':')) {
        fs.writeFileSync(args[2], content);
      }
    };

    const copyInputs: TaskInputs = { ...inputs, sourceTransfer: 'copy' };

    const dockerSteps = (runner: FakeRunner): string[] =>
      runner.calls.filter((call) => !call.args.includes('version')).map((call) => call.args[0]);

    it('issues create, cp-in, start, cp-out and rm in that order', async () => {
      const runner = new FakeRunner(writeReportOnCopyOut(reportBody));
      await runScan({
        defaults,
        runners,
        databases,
        inputs: copyInputs,
        agent,
        scanIndex: 0,
        processRunner: runner,
        publisher: new Publisher((line) => lines.push(line)),
        credentials: {},
      });
      expect(dockerSteps(runner)).toEqual(['create', 'cp', 'start', 'cp', 'rm']);
    });

    it('never passes -v for the sources or the cache mount', async () => {
      const runner = new FakeRunner(writeReportOnCopyOut(reportBody));
      await runScan({
        defaults,
        runners,
        databases,
        inputs: copyInputs,
        agent,
        scanIndex: 0,
        processRunner: runner,
        publisher: new Publisher((line) => lines.push(line)),
        credentials: {},
      });
      expect(runner.calls.some((call) => call.args.includes('-v'))).toBe(false);
    });

    it('reads the report from the host path after it is copied out of the container', async () => {
      const runner = new FakeRunner(writeReportOnCopyOut(reportBody));
      const result = await runScan({
        defaults,
        runners,
        databases,
        inputs: copyInputs,
        agent,
        scanIndex: 0,
        processRunner: runner,
        publisher: new Publisher((line) => lines.push(line)),
        credentials: {},
      });
      expect(result.reportPath).toBe(path.join(workspace, '.trivy', 'report-0.json'));
      expect(result.report.findings).toHaveLength(1);
      expect(result.gate.outcome).toBe('failed');
    });

    it('still removes the container when a step mid-sequence fails, and does not attempt start or cp-out', async () => {
      const runner = new FakeRunner();
      runner.results = [
        { exitCode: 0, stdout: '', stderr: '', timedOut: false }, // create
        { exitCode: 1, stdout: '', stderr: 'cp: no such file or directory', timedOut: false }, // cp-in fails
      ];
      await expect(
        runScan({
          defaults,
          runners,
          databases,
          inputs: copyInputs,
          agent,
          scanIndex: 0,
          processRunner: runner,
          publisher: new Publisher((line) => lines.push(line)),
          credentials: {},
        }),
      ).rejects.toThrow();
      expect(dockerSteps(runner)).toEqual(['create', 'cp', 'rm']);
    });

    it('removes the container exactly once after a timeout, without runScan issuing a second rm', async () => {
      const runner = new FakeRunner();
      runner.results = [
        { exitCode: 0, stdout: '', stderr: '', timedOut: false }, // create
        { exitCode: 0, stdout: '', stderr: '', timedOut: false }, // cp-in
        { exitCode: 124, stdout: '', stderr: '', timedOut: true }, // start times out
      ];
      await expect(
        runScan({
          defaults,
          runners,
          databases,
          inputs: copyInputs,
          agent,
          scanIndex: 0,
          processRunner: runner,
          publisher: new Publisher((line) => lines.push(line)),
          credentials: {},
        }),
      ).rejects.toThrow(/timeoutMinutes/);
      expect(runner.calls.filter((call) => call.args[0] === 'rm')).toHaveLength(1);
    });

    it('mount mode still issues a single plain docker run for the scan, unaffected by copy mode existing', async () => {
      const runner = new FakeRunner(writeReport);
      await invoke(runner);
      expect(dockerSteps(runner)).toEqual(['run']);
    });

    it('runs the sarif extra format through the same create/cp/start/cp/rm sequence, with its own container name', async () => {
      const runner = new FakeRunner(writeReportOnCopyOut(reportBody));
      const result = await runScan({
        defaults,
        runners,
        databases,
        inputs: { ...copyInputs, formats: ['json', 'sarif'] },
        agent,
        scanIndex: 0,
        processRunner: runner,
        publisher: new Publisher((line) => lines.push(line)),
        credentials: {},
      });

      expect(result.gate.outcome).toBe('failed');
      const names = runner.calls
        .filter((call) => call.args.includes('--name'))
        .map((call) => call.args[call.args.indexOf('--name') + 1]);
      expect(names).toEqual(['trivyscan-1042-0', 'trivyscan-1042-0-sarif']);
      expect(dockerSteps(runner)).toEqual([
        'create',
        'cp',
        'start',
        'cp',
        'rm',
        'create',
        'cp',
        'start',
        'cp',
        'rm',
      ]);
      expect(lines.some((line) => line.includes('CodeAnalysisLogs'))).toBe(true);
    });

    it('runs the sbom extra format through the copy sequence too, never falling back to a mount', async () => {
      const runner = new FakeRunner(writeReportOnCopyOut(reportBody));
      await runScan({
        defaults,
        runners,
        databases,
        inputs: { ...copyInputs, generateSbom: 'cyclonedx' },
        agent,
        scanIndex: 0,
        processRunner: runner,
        publisher: new Publisher((line) => lines.push(line)),
        credentials: {},
      });
      expect(runner.calls.some((call) => call.args.includes('-v'))).toBe(false);
      expect(lines.some((line) => line.includes('TrivySBOM'))).toBe(true);
    });
  });
});
