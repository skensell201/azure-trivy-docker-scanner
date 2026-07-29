import { validateRunner, validateCatalog, validateDefaults } from '../validation';
import { DefaultsConfig, RunnerConfig, Scanner, Severity } from '../types';

const runner = (over: Partial<RunnerConfig> = {}): RunnerConfig => ({
  alias: 'baseline',
  image: 'reg.corp/trivy:0.58.1',
  isDefault: true,
  enabled: true,
  ...over,
});

const defaults = (over: Partial<DefaultsConfig> = {}): DefaultsConfig => ({
  dbRepository: 'reg.corp/trivy-db:2',
  ...over,
});

describe('validateRunner', () => {
  it('accepts a well-formed runner', () => {
    expect(validateRunner(runner())).toEqual([]);
  });

  it('rejects an alias that is not lowercase kebab', () => {
    const issues = validateRunner(runner({ alias: 'Base Line' }));
    expect(issues).toEqual([{ field: 'alias', message: expect.stringContaining('lowercase') }]);
  });

  it('requires an image reference', () => {
    const issues = validateRunner(runner({ image: '' }));
    expect(issues).toEqual([{ field: 'image', message: expect.stringContaining('required') }]);
  });

  it('requires an explicit tag on the image', () => {
    const issues = validateRunner(runner({ image: 'reg.corp/trivy' }));
    expect(issues).toEqual([{ field: 'image', message: expect.stringContaining('tag') }]);
  });

  it('rejects the latest tag because it is not reproducible', () => {
    const issues = validateRunner(runner({ image: 'reg.corp/trivy:latest' }));
    expect(issues).toEqual([{ field: 'image', message: expect.stringContaining('latest') }]);
  });

  it('rejects unparsable extra docker args', () => {
    const issues = validateRunner(runner({ extraDockerArgs: '--label "oops' }));
    expect(issues).toEqual([
      { field: 'extraDockerArgs', message: expect.stringContaining('Unterminated quote') },
    ]);
  });

  it('rejects a non-string extraDockerArgs instead of crashing on iteration', () => {
    const issues = validateRunner(runner({ extraDockerArgs: 5 as unknown as string }));
    expect(issues).toEqual([
      { field: 'extraDockerArgs', message: expect.stringContaining('string') },
    ]);
  });

  it('reports every failing field at once instead of stopping at the first', () => {
    const issues = validateRunner(runner({ alias: 'Bad Alias', image: '' }));
    expect(issues).toEqual([
      { field: 'alias', message: expect.stringContaining('lowercase') },
      { field: 'image', message: expect.stringContaining('required') },
    ]);
  });

  it('rejects a missing tag on a registry with an explicit port, without confusing the port for a tag', () => {
    const issues = validateRunner(runner({ image: 'reg.corp:5000/trivy' }));
    expect(issues).toEqual([{ field: 'image', message: expect.stringContaining('tag') }]);
  });

  it('accepts an explicit tag on a registry with an explicit port', () => {
    expect(validateRunner(runner({ image: 'reg.corp:5000/trivy:0.58.1' }))).toEqual([]);
  });

  // --- Fix 1: shape guards, so a hand-edited document reports an issue instead of throwing ---

  it('rejects a non-object runner instead of throwing', () => {
    expect(validateRunner(null)).toEqual([{ field: 'runner', message: expect.stringContaining('object') }]);
    expect(validateRunner('nope')).toEqual([{ field: 'runner', message: expect.stringContaining('object') }]);
  });

  it('rejects a non-string image instead of crashing on .trim', () => {
    const issues = validateRunner(runner({ image: 5 as unknown as string }));
    expect(issues).toEqual([{ field: 'image', message: expect.stringContaining('required') }]);
  });

  // --- Fix 2: wrong-typed values must be flagged, not silently accepted ---

  it('rejects a numeric alias instead of coercing it to a string', () => {
    const issues = validateRunner(runner({ alias: 42 as unknown as string }));
    expect(issues).toEqual([{ field: 'alias', message: expect.stringContaining('lowercase') }]);
  });

  // --- Fix 3: mutation-tested gaps ---

  it('accepts a two-character alias at the lower length boundary', () => {
    expect(validateRunner(runner({ alias: 'ab' }))).toEqual([]);
  });

  it('rejects a 32-character alias exceeding the upper length boundary', () => {
    const issues = validateRunner(runner({ alias: 'a'.repeat(32) }));
    expect(issues).toEqual([{ field: 'alias', message: expect.stringContaining('lowercase') }]);
  });

  it('accepts a repository name containing "latest" as a substring, only rejecting the tag itself', () => {
    expect(validateRunner(runner({ image: 'reg.corp/latest-trivy:0.58.1' }))).toEqual([]);
  });

  // --- Fix 4: the tag rule must reject nonsense but keep accepting digests ---

  it('rejects an empty tag', () => {
    const issues = validateRunner(runner({ image: 'reg.corp/trivy:' }));
    expect(issues).toEqual([{ field: 'image', message: expect.stringContaining('tag') }]);
  });

  it('rejects trailing text read as part of the tag', () => {
    const issues = validateRunner(runner({ image: 'reg.corp/trivy:0.58.1 --privileged' }));
    expect(issues).toEqual([{ field: 'image', message: expect.stringContaining('tag') }]);
  });

  it('accepts a digest reference', () => {
    expect(validateRunner(runner({ image: `reg.corp/trivy@sha256:${'a'.repeat(64)}` }))).toEqual([]);
  });

  it('accepts a digest reference on a registry with an explicit port', () => {
    expect(
      validateRunner(runner({ image: `reg.corp:5000/trivy@sha256:${'a'.repeat(64)}` })),
    ).toEqual([]);
  });

  it('accepts a digest reference alongside an explicit tag', () => {
    expect(
      validateRunner(runner({ image: `reg.corp/trivy:0.58.1@sha256:${'a'.repeat(64)}` })),
    ).toEqual([]);
  });
});

describe('validateCatalog', () => {
  it('accepts a catalog with unique aliases and exactly one default', () => {
    expect(validateCatalog([runner(), runner({ alias: 'hardened', isDefault: false })])).toEqual([]);
  });

  it('rejects duplicate aliases naming the duplicate', () => {
    const issues = validateCatalog([runner(), runner({ isDefault: false })]);
    expect(issues).toEqual([{ field: 'alias', message: expect.stringContaining('baseline') }]);
  });

  it('rejects more than one default runner', () => {
    const issues = validateCatalog([runner(), runner({ alias: 'hardened' })]);
    expect(issues).toEqual([
      { field: 'isDefault', message: expect.stringContaining('exactly one') },
    ]);
  });

  it('rejects a catalog whose only default runner is disabled', () => {
    const issues = validateCatalog([runner({ enabled: false })]);
    expect(issues).toEqual([{ field: 'isDefault', message: expect.stringContaining('disabled') }]);
  });

  it('rejects an empty catalog instead of throwing', () => {
    const issues = validateCatalog([]);
    expect(issues).toEqual([{ field: 'isDefault', message: expect.stringContaining('exactly one') }]);
  });

  // --- Fix 1: shape guards ---

  it('rejects a non-array catalog instead of throwing', () => {
    expect(validateCatalog(null)).toEqual([{ field: 'runners', message: expect.stringContaining('list of runners') }]);
    expect(validateCatalog({})).toEqual([{ field: 'runners', message: expect.stringContaining('list of runners') }]);
  });

  it('rejects a non-object catalog entry, naming its index, instead of dereferencing it', () => {
    const issues = validateCatalog([null, runner()]);
    expect(issues).toEqual([{ field: 'runners[0]', message: expect.stringContaining('index 0') }]);
  });

  it('reports a sensible issue instead of a confusing one when a caller passes a single runner instead of an array', () => {
    expect(validateCatalog(runner())).toEqual([
      { field: 'runners', message: expect.stringContaining('list of runners') },
    ]);
  });

  // --- Fix 3: mutation-tested gap ---

  it('accepts a default runner with enabled omitted, since omitted means enabled', () => {
    const catalogRunner: RunnerConfig = {
      alias: 'baseline',
      image: 'reg.corp/trivy:0.58.1',
      isDefault: true,
    };
    expect(validateCatalog([catalogRunner])).toEqual([]);
  });

  // --- Fix 5: message quality ---

  it('reports a triple-duplicated alias only once', () => {
    const issues = validateCatalog([
      runner(),
      runner({ isDefault: false }),
      runner({ isDefault: false }),
    ]);
    expect(issues.filter((issue) => issue.field === 'alias')).toEqual([
      { field: 'alias', message: expect.stringContaining('baseline') },
    ]);
  });

  it('names every offending runner when more than one is marked default', () => {
    const issues = validateCatalog([runner(), runner({ alias: 'hardened' })]);
    expect(issues).toEqual([
      {
        field: 'isDefault',
        message: 'The catalog must contain exactly one default runner, found 2: "baseline", "hardened".',
      },
    ]);
  });

  // --- Fix 6: the seam between validateCatalog and validateRunner ---

  it('does not validate individual runner fields, only cross-runner invariants', () => {
    expect(validateCatalog([{ alias: 'BAD', image: 'x:latest', isDefault: true }])).toEqual([]);
  });
});

describe('validateDefaults', () => {
  it('accepts minimal defaults', () => {
    expect(validateDefaults(defaults())).toEqual([]);
  });

  it('requires a db repository because the target environment has no internet', () => {
    const issues = validateDefaults(defaults({ dbRepository: '  ' }));
    expect(issues).toEqual([
      { field: 'dbRepository', message: expect.stringContaining('required') },
    ]);
  });

  it('rejects a non-positive timeout', () => {
    const issues = validateDefaults(defaults({ timeoutMinutes: 0 }));
    expect(issues).toEqual([
      { field: 'timeoutMinutes', message: expect.stringContaining('greater than zero') },
    ]);
  });

  it('rejects an empty severity list', () => {
    const issues = validateDefaults(defaults({ severities: [] }));
    expect(issues).toEqual([
      { field: 'severities', message: expect.stringContaining('at least one') },
    ]);
  });

  // --- Fix 1: shape guards ---

  it('rejects non-object defaults instead of throwing', () => {
    expect(validateDefaults(null)).toEqual([{ field: 'defaults', message: expect.stringContaining('object') }]);
  });

  it('rejects a non-string dbRepository instead of crashing on .trim', () => {
    const issues = validateDefaults(defaults({ dbRepository: 5 as unknown as string }));
    expect(issues).toEqual([{ field: 'dbRepository', message: expect.stringContaining('required') }]);
  });

  it('rejects severities: null instead of crashing on .length', () => {
    const issues = validateDefaults(defaults({ severities: null as unknown as Severity[] }));
    expect(issues).toEqual([{ field: 'severities', message: expect.stringContaining('at least one') }]);
  });

  // --- Fix 2: wrong-typed values must be flagged, not silently accepted ---

  it('rejects a non-numeric timeout instead of silently accepting it', () => {
    const issues = validateDefaults(defaults({ timeoutMinutes: 'abc' as unknown as number }));
    expect(issues).toEqual([{ field: 'timeoutMinutes', message: expect.stringContaining('greater than zero') }]);
  });

  it('rejects a NaN timeout instead of letting it propagate to the docker invocation', () => {
    const issues = validateDefaults(defaults({ timeoutMinutes: NaN }));
    expect(issues).toEqual([{ field: 'timeoutMinutes', message: expect.stringContaining('greater than zero') }]);
  });

  it('rejects severities given as a string instead of an array', () => {
    const issues = validateDefaults(defaults({ severities: 'HIGH' as unknown as Severity[] }));
    expect(issues).toEqual([{ field: 'severities', message: expect.stringContaining('at least one') }]);
  });

  it('rejects scanners given as a plain object instead of an array', () => {
    const issues = validateDefaults(defaults({ scanners: {} as unknown as Scanner[] }));
    expect(issues).toEqual([{ field: 'scanners', message: expect.stringContaining('at least one') }]);
  });

  // --- Fix 3: mutation-tested gap ---

  it('rejects an empty scanners list', () => {
    const issues = validateDefaults(defaults({ scanners: [] }));
    expect(issues).toEqual([{ field: 'scanners', message: expect.stringContaining('at least one') }]);
  });
});
