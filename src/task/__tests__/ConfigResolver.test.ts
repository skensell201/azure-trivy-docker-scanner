import { resolveConfig, PolicyViolationError, RunnerNotFoundError } from '../ConfigResolver';
import { AgentContext, DefaultsConfig, RunnerConfig, TaskInputs } from '../../shared/types';

const runners: RunnerConfig[] = [
  { alias: 'baseline', image: 'reg.corp/trivy:0.58.1', isDefault: true, enabled: true },
  { alias: 'hardened', image: 'reg.corp/trivy-fips:0.58.1', enabled: true },
  { alias: 'legacy', image: 'reg.corp/trivy:0.44.0', enabled: false },
];

const defaults: DefaultsConfig = { dbRepository: 'reg.corp/trivy-db:2' };

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
        runners: [{ alias: 'legacy', image: 'reg.corp/trivy:0.44.0', enabled: false }],
        inputs: inputs({ runner: 'legacy' }),
        agent,
        scanIndex: 0,
      }),
    ).toThrow(RunnerNotFoundError);
  });
});
