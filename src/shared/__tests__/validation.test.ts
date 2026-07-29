import { validateRunner, validateCatalog, validateDefaults } from '../validation';
import { DefaultsConfig, RunnerConfig } from '../types';

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
});
