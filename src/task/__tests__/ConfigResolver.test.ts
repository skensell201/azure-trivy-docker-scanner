import { resolveConfig, PolicyViolationError, RunnerNotFoundError } from '../ConfigResolver';
import { AgentContext, DefaultsConfig, RunnerConfig, TaskInputs } from '../../shared/types';

const runners: RunnerConfig[] = [
  { alias: 'baseline', image: 'registry.example.com/trivy:0.58.1', isDefault: true, enabled: true },
  { alias: 'hardened', image: 'registry.example.com/trivy-fips:0.58.1', enabled: true },
  { alias: 'legacy', image: 'registry.example.com/trivy:0.44.0', enabled: false },
];

const defaults: DefaultsConfig = { dbRepository: 'registry.example.com/trivy-db:2' };

const agent: AgentContext = {
  sourcesDir: '/agent/_work/1/s',
  agentHomeDir: '/agent',
  tempDir: '/agent/_work/_temp',
  buildId: '1042',
};

const inputs = (over: Partial<TaskInputs> = {}): TaskInputs => ({
  scanType: 'image',
  target: 'app:1.4.2',
  ...over,
});

describe('resolveConfig', () => {
  it('falls back to the default runner when the pipeline names none', () => {
    const config = resolveConfig({ defaults, runners, inputs: inputs(), agent, scanIndex: 0 });
    expect(config.runner.alias).toBe('baseline');
  });

  it('applies built-in defaults when neither admin nor pipeline set a value', () => {
    const config = resolveConfig({ defaults, runners, inputs: inputs(), agent, scanIndex: 0 });
    expect(config.severities).toEqual(['CRITICAL', 'HIGH']);
    expect(config.scanners).toEqual(['vuln', 'secret']);
    expect(config.failOn).toBe('CRITICAL');
    expect(config.timeoutMinutes).toBe(10);
    expect(config.ignoreUnfixed).toBe(false);
    expect(config.cacheDir).toBe('/agent/_trivy-cache');
  });

  it('prefers admin defaults over built-in defaults', () => {
    const config = resolveConfig({
      defaults: { ...defaults, failOn: 'HIGH', timeoutMinutes: 25 },
      runners,
      inputs: inputs(),
      agent,
      scanIndex: 0,
    });
    expect(config.failOn).toBe('HIGH');
    expect(config.timeoutMinutes).toBe(25);
  });

  it('lets the pipeline override a field when policy allows it', () => {
    const config = resolveConfig({
      defaults: { ...defaults, failOn: 'CRITICAL' },
      runners,
      inputs: inputs({ failOn: 'LOW' }),
      agent,
      scanIndex: 0,
    });
    expect(config.failOn).toBe('LOW');
  });

  it('rejects an override of a field the policy withholds', () => {
    expect(() =>
      resolveConfig({
        defaults: { ...defaults, allowOverrides: ['severities'] },
        runners,
        inputs: inputs({ failOn: 'LOW' }),
        agent,
        scanIndex: 0,
      }),
    ).toThrow(PolicyViolationError);
  });

  it('names both the field and the allowed fields when policy rejects an override', () => {
    expect(() =>
      resolveConfig({
        defaults: { ...defaults, allowOverrides: ['severities'] },
        runners,
        inputs: inputs({ failOn: 'LOW' }),
        agent,
        scanIndex: 0,
      }),
    ).toThrow(/failOn.*severities/s);
  });

  it('lists the available aliases when the requested runner does not exist', () => {
    expect(() =>
      resolveConfig({ defaults, runners, inputs: inputs({ runner: 'nope' }), agent, scanIndex: 0 }),
    ).toThrow(/baseline, hardened/);
  });

  it('refuses a disabled runner', () => {
    expect(() =>
      resolveConfig({ defaults, runners, inputs: inputs({ runner: 'legacy' }), agent, scanIndex: 0 }),
    ).toThrow(RunnerNotFoundError);
  });

  it('fails when the catalog is empty', () => {
    expect(() =>
      resolveConfig({ defaults, runners: [], inputs: inputs(), agent, scanIndex: 0 }),
    ).toThrow(/no runners/i);
  });

  it('carries agent context into the resolved config', () => {
    const config = resolveConfig({ defaults, runners, inputs: inputs(), agent, scanIndex: 2 });
    expect(config.sourcesDir).toBe('/agent/_work/1/s');
    expect(config.buildId).toBe('1042');
    expect(config.scanIndex).toBe(2);
  });

  it('reports "none" when an empty allowOverrides withholds every field', () => {
    expect(() =>
      resolveConfig({
        defaults: { ...defaults, allowOverrides: [] },
        runners,
        inputs: inputs({ failOn: 'LOW' }),
        agent,
        scanIndex: 0,
      }),
    ).toThrow(/Overridable fields: none/);
  });

  it('lets an explicit false override win over an admin default of true', () => {
    const config = resolveConfig({
      defaults: { ...defaults, ignoreUnfixed: true },
      runners,
      inputs: inputs({ ignoreUnfixed: false }),
      agent,
      scanIndex: 0,
    });
    expect(config.ignoreUnfixed).toBe(false);
  });

  it('subjects a pipeline-named runner to the "runner" policy like any other field', () => {
    expect(() =>
      resolveConfig({
        defaults: { ...defaults, allowOverrides: ['severities'] },
        runners,
        inputs: inputs({ runner: 'hardened' }),
        agent,
        scanIndex: 0,
      }),
    ).toThrow(PolicyViolationError);
  });

  it('reports RunnerNotFoundError when the requested runner is disabled and none other is enabled', () => {
    expect(() =>
      resolveConfig({
        defaults,
        runners: [{ alias: 'legacy', image: 'registry.example.com/trivy:0.44.0', enabled: false }],
        inputs: inputs({ runner: 'legacy' }),
        agent,
        scanIndex: 0,
      }),
    ).toThrow(RunnerNotFoundError);
  });
});

describe('Fix 1: policy gates useDockerSocket, extraTrivyArgs and ignoreFile', () => {
  it('rejects a useDockerSocket override when the policy withholds it', () => {
    expect(() =>
      resolveConfig({
        defaults: { ...defaults, allowOverrides: [] },
        runners,
        inputs: inputs({ useDockerSocket: true }),
        agent,
        scanIndex: 0,
      }),
    ).toThrow(PolicyViolationError);
  });

  it('accepts a useDockerSocket override when no policy is configured', () => {
    const config = resolveConfig({
      defaults,
      runners,
      inputs: inputs({ useDockerSocket: true }),
      agent,
      scanIndex: 0,
    });
    expect(config.useDockerSocket).toBe(true);
  });

  it('rejects an extraTrivyArgs override when the policy withholds it', () => {
    expect(() =>
      resolveConfig({
        defaults: { ...defaults, allowOverrides: [] },
        runners,
        inputs: inputs({ extraTrivyArgs: '--severity LOW' }),
        agent,
        scanIndex: 0,
      }),
    ).toThrow(PolicyViolationError);
  });

  it('accepts an extraTrivyArgs override when no policy is configured', () => {
    const config = resolveConfig({
      defaults,
      runners,
      inputs: inputs({ extraTrivyArgs: '--offline-scan' }),
      agent,
      scanIndex: 0,
    });
    expect(config.extraTrivyArgs).toBe('--offline-scan');
  });

  it('rejects an ignoreFile override when the policy withholds it', () => {
    expect(() =>
      resolveConfig({
        defaults: { ...defaults, allowOverrides: [] },
        runners,
        inputs: inputs({ ignoreFile: '.trivyignore' }),
        agent,
        scanIndex: 0,
      }),
    ).toThrow(PolicyViolationError);
  });

  it('accepts an ignoreFile override when no policy is configured', () => {
    const config = resolveConfig({
      defaults,
      runners,
      inputs: inputs({ ignoreFile: '.trivyignore' }),
      agent,
      scanIndex: 0,
    });
    expect(config.ignoreFile).toBe('.trivyignore');
  });
});

describe('Fix 4: whole-object contract', () => {
  it('pins every built-in default in one assertion when nothing else is set', () => {
    const config = resolveConfig({ defaults, runners, inputs: inputs(), agent, scanIndex: 0 });
    expect(config).toEqual({
      runner: { alias: 'baseline', image: 'registry.example.com/trivy:0.58.1', isDefault: true, enabled: true },
      scanType: 'image',
      target: 'app:1.4.2',
      severities: ['CRITICAL', 'HIGH'],
      scanners: ['vuln', 'secret'],
      failOn: 'CRITICAL',
      ignoreUnfixed: false,
      skipDbUpdate: false,
      timeoutMinutes: 10,
      dbRepository: 'registry.example.com/trivy-db:2',
      javaDbRepository: undefined,
      cacheDir: '/agent/_trivy-cache',
      sourcesDir: '/agent/_work/1/s',
      workingDirectory: undefined,
      ignoreFile: undefined,
      useDockerSocket: false,
      formats: ['table', 'json'],
      generateSbom: 'off',
      publishArtifact: true,
      publishTestResults: false,
      extraTrivyArgs: undefined,
      buildId: '1042',
      scanIndex: 0,
      sourceTransfer: 'mount',
    });
  });

  it('pins every precedence and pass-through rule when both admin and pipeline set every field', () => {
    const fullDefaults: DefaultsConfig = {
      dbRepository: 'registry.example.com/trivy-db:2',
      javaDbRepository: 'registry.example.com/trivy-java-db:1',
      dbRegistryUsername: 'admin-user',
      dbRegistryPassword: 'admin-pass',
      cacheDir: '/admin/cache',
      skipDbUpdate: true,
      severities: ['HIGH'],
      scanners: ['vuln'],
      failOn: 'HIGH',
      ignoreUnfixed: true,
      timeoutMinutes: 20,
      // allowOverrides omitted: everything is overridable.
    };

    const fullInputs: TaskInputs = {
      scanType: 'filesystem',
      target: '.',
      runner: 'hardened',
      severities: ['LOW', 'MEDIUM'],
      scanners: ['secret', 'license'],
      failOn: 'LOW',
      ignoreUnfixed: false,
      ignoreFile: '.trivyignore',
      timeoutMinutes: 5,
      skipDbUpdate: false,
      useDockerSocket: true,
      formats: ['json', 'sarif'],
      generateSbom: 'cyclonedx',
      publishArtifact: false,
      publishTestResults: true,
      extraTrivyArgs: '--offline-scan',
      workingDirectory: 'subdir',
      sourceTransfer: 'copy',
    };

    const config = resolveConfig({
      defaults: fullDefaults,
      runners,
      inputs: fullInputs,
      agent,
      scanIndex: 3,
    });

    expect(config).toEqual({
      runner: { alias: 'hardened', image: 'registry.example.com/trivy-fips:0.58.1', enabled: true },
      scanType: 'filesystem',
      target: '.',
      severities: ['LOW', 'MEDIUM'],
      scanners: ['secret', 'license'],
      failOn: 'LOW',
      ignoreUnfixed: false,
      skipDbUpdate: false,
      timeoutMinutes: 5,
      dbRepository: 'registry.example.com/trivy-db:2',
      javaDbRepository: 'registry.example.com/trivy-java-db:1',
      cacheDir: '/admin/cache',
      sourcesDir: '/agent/_work/1/s',
      workingDirectory: 'subdir',
      ignoreFile: '.trivyignore',
      useDockerSocket: true,
      formats: ['json', 'sarif'],
      generateSbom: 'cyclonedx',
      publishArtifact: false,
      publishTestResults: true,
      extraTrivyArgs: '--offline-scan',
      buildId: '1042',
      scanIndex: 3,
      sourceTransfer: 'copy',
    });
  });

  it('defaults sourceTransfer to mount and is not gated by allowOverrides', () => {
    const config = resolveConfig({
      defaults: { ...defaults, allowOverrides: [] },
      runners,
      inputs: inputs({ sourceTransfer: 'copy' }),
      agent,
      scanIndex: 0,
    });
    expect(config.sourceTransfer).toBe('copy');
  });

  // publishTestResults changes only which views the already-evaluated gate result is shown
  // through (see the doc comment on TaskInputs.publishTestResults) -- it has no gate-integrity
  // implication, so, like publishArtifact and sourceTransfer, it is never gated by allowOverrides.
  it('defaults publishTestResults to false and is not gated by allowOverrides', () => {
    const config = resolveConfig({
      defaults: { ...defaults, allowOverrides: [] },
      runners,
      inputs: inputs({ publishTestResults: true }),
      agent,
      scanIndex: 0,
    });
    expect(config.publishTestResults).toBe(true);
  });
});

describe('Fix 5: actionable runner and policy error messages', () => {
  it('says no runners are enabled when the requested alias does not exist and none are enabled', () => {
    expect(() =>
      resolveConfig({
        defaults,
        runners: [{ alias: 'legacy', image: 'registry.example.com/trivy:0.44.0', enabled: false }],
        inputs: inputs({ runner: 'nope' }),
        agent,
        scanIndex: 0,
      }),
    ).toThrow(/no runners are currently enabled/i);
  });

  it('distinguishes an unknown alias from a disabled one', () => {
    let unknownMessage = '';
    let disabledMessage = '';
    try {
      resolveConfig({ defaults, runners, inputs: inputs({ runner: 'nope' }), agent, scanIndex: 0 });
    } catch (e) {
      unknownMessage = (e as Error).message;
    }
    try {
      resolveConfig({ defaults, runners, inputs: inputs({ runner: 'legacy' }), agent, scanIndex: 0 });
    } catch (e) {
      disabledMessage = (e as Error).message;
    }
    expect(unknownMessage).toMatch(/does not exist/);
    expect(disabledMessage).toMatch(/disabled/);
    expect(unknownMessage).not.toEqual(disabledMessage);
  });

  it('says the default runner is disabled rather than unconfigured, matching validateCatalog wording', () => {
    expect(() =>
      resolveConfig({
        defaults,
        runners: [{ alias: 'baseline', image: 'registry.example.com/trivy:0.58.1', isDefault: true, enabled: false }],
        inputs: inputs(),
        agent,
        scanIndex: 0,
      }),
    ).toThrow(/Default runner "baseline" is disabled\. Enable it or mark another runner as default\./);
  });

  it('treats an empty runner input as absent rather than a policy-triggering override', () => {
    const config = resolveConfig({
      defaults: { ...defaults, allowOverrides: ['severities'] },
      runners,
      inputs: inputs({ runner: '' }),
      agent,
      scanIndex: 0,
    });
    expect(config.runner.alias).toBe('baseline');
  });

  it('names the value the collection enforces in the policy violation message', () => {
    expect(() =>
      resolveConfig({
        defaults: { ...defaults, allowOverrides: ['severities'], failOn: 'CRITICAL' },
        runners,
        inputs: inputs({ failOn: 'LOW' }),
        agent,
        scanIndex: 0,
      }),
    ).toThrow(/collection sets failOn to "CRITICAL"/);
  });
});

describe('Fix 6: every policy violation is reported together', () => {
  it('names every offending field in a single error instead of stopping at the first', () => {
    const attempt = () =>
      resolveConfig({
        defaults: { ...defaults, allowOverrides: ['scanners'] },
        runners,
        inputs: inputs({ runner: 'hardened', failOn: 'LOW' }),
        agent,
        scanIndex: 0,
      });

    expect(attempt).toThrow(PolicyViolationError);

    let thrown: Error | undefined;
    try {
      attempt();
    } catch (e) {
      thrown = e as Error;
    }
    expect(thrown).toBeDefined();
    expect(thrown!.message).toMatch(/runner/);
    expect(thrown!.message).toMatch(/failOn/);
    expect(thrown!.message).toMatch(/scanners/);
  });
});
