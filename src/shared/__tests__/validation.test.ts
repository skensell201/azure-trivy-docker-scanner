import {
  validateRunner,
  validateCatalog,
  validateDefaults,
  validateDatabase,
  validateDatabaseCatalogue,
  validateRunnerDatabaseLinks,
} from '../validation';
import { DatabaseConfig, DefaultsConfig, RunnerConfig, Scanner, Severity } from '../types';

const runner = (over: Partial<RunnerConfig> = {}): RunnerConfig => ({
  alias: 'baseline',
  image: 'registry.example.com/trivy:0.58.1',
  isDefault: true,
  enabled: true,
  ...over,
});

const defaults = (over: Partial<DefaultsConfig> = {}): DefaultsConfig => ({
  dbRepository: 'registry.example.com/trivy-db:2',
  ...over,
});

const database = (over: Partial<DatabaseConfig> = {}): DatabaseConfig => ({
  alias: 'baseline-db',
  repository: 'registry.example.com/trivy-db:2',
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
    const issues = validateRunner(runner({ image: 'registry.example.com/trivy' }));
    expect(issues).toEqual([{ field: 'image', message: expect.stringContaining('tag') }]);
  });

  it('rejects the latest tag because it is not reproducible', () => {
    const issues = validateRunner(runner({ image: 'registry.example.com/trivy:latest' }));
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
    const issues = validateRunner(runner({ image: 'registry.example.com:5000/trivy' }));
    expect(issues).toEqual([{ field: 'image', message: expect.stringContaining('tag') }]);
  });

  it('accepts an explicit tag on a registry with an explicit port', () => {
    expect(validateRunner(runner({ image: 'registry.example.com:5000/trivy:0.58.1' }))).toEqual([]);
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
    expect(validateRunner(runner({ image: 'registry.example.com/latest-trivy:0.58.1' }))).toEqual([]);
  });

  // --- Fix 4: the tag rule must reject nonsense but keep accepting digests ---

  it('rejects an empty tag', () => {
    const issues = validateRunner(runner({ image: 'registry.example.com/trivy:' }));
    expect(issues).toEqual([{ field: 'image', message: expect.stringContaining('tag') }]);
  });

  it('rejects trailing text read as part of the tag', () => {
    const issues = validateRunner(runner({ image: 'registry.example.com/trivy:0.58.1 --privileged' }));
    expect(issues).toEqual([{ field: 'image', message: expect.stringContaining('tag') }]);
  });

  it('accepts a digest reference', () => {
    expect(validateRunner(runner({ image: `registry.example.com/trivy@sha256:${'a'.repeat(64)}` }))).toEqual([]);
  });

  it('accepts a digest reference on a registry with an explicit port', () => {
    expect(
      validateRunner(runner({ image: `registry.example.com:5000/trivy@sha256:${'a'.repeat(64)}` })),
    ).toEqual([]);
  });

  it('accepts a digest reference alongside an explicit tag', () => {
    expect(
      validateRunner(runner({ image: `registry.example.com/trivy:0.58.1@sha256:${'a'.repeat(64)}` })),
    ).toEqual([]);
  });

  // --- registry credentials: administrator-entered pair, neither half may stand alone ---

  it('accepts a runner with neither registry credential set', () => {
    expect(validateRunner(runner())).toEqual([]);
  });

  it('accepts a runner with both registry credentials set', () => {
    expect(
      validateRunner(runner({ registryUsername: 'svc', registryPassword: 'p@ss' })),
    ).toEqual([]);
  });

  it('rejects a registryUsername without a registryPassword, naming the missing field', () => {
    const issues = validateRunner(runner({ registryUsername: 'svc' }));
    expect(issues).toEqual([
      { field: 'registryPassword', message: expect.stringContaining('registryPassword') },
    ]);
  });

  it('rejects a registryPassword without a registryUsername, naming the missing field', () => {
    const issues = validateRunner(runner({ registryPassword: 'p@ss' }));
    expect(issues).toEqual([
      { field: 'registryUsername', message: expect.stringContaining('registryUsername') },
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
      image: 'registry.example.com/trivy:0.58.1',
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

  // dbRepository is deprecated (see DefaultsConfig's doc comment): a fully migrated
  // configuration has no database settings in `defaults` at all, so its absence -- or any
  // other value -- is no longer validated here. The equivalent "is a database actually
  // configured" check has moved to validateDatabaseCatalogue and validateRunnerDatabaseLinks.

  it('accepts defaults with dbRepository omitted entirely, since it is now optional', () => {
    expect(validateDefaults({})).toEqual([]);
  });

  it('accepts a blank dbRepository instead of requiring it, now that the field is deprecated', () => {
    expect(validateDefaults(defaults({ dbRepository: '  ' }))).toEqual([]);
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

  it('accepts a non-string dbRepository instead of crashing, since the field is no longer validated', () => {
    expect(validateDefaults(defaults({ dbRepository: 5 as unknown as string }))).toEqual([]);
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

  // --- cacheDir mount safety: a hand-edited document could point -v at host root ---

  it('accepts a well-formed cacheDir', () => {
    expect(validateDefaults(defaults({ cacheDir: '/agent/_trivy-cache' }))).toEqual([]);
  });

  it('rejects a non-string cacheDir instead of crashing', () => {
    const issues = validateDefaults(defaults({ cacheDir: 5 as unknown as string }));
    expect(issues).toEqual([{ field: 'cacheDir', message: expect.stringContaining('string') }]);
  });

  it('rejects a relative cacheDir', () => {
    const issues = validateDefaults(defaults({ cacheDir: 'relative/cache' }));
    expect(issues).toEqual([{ field: 'cacheDir', message: expect.stringContaining('absolute') }]);
  });

  it('rejects cacheDir set to the filesystem root, which would mount host root read-write', () => {
    const issues = validateDefaults(defaults({ cacheDir: '/' }));
    expect(issues).toEqual([{ field: 'cacheDir', message: expect.stringContaining('root') }]);
  });

  it('rejects a bare root-level directory such as /etc as cacheDir', () => {
    const issues = validateDefaults(defaults({ cacheDir: '/etc' }));
    expect(issues).toEqual([{ field: 'cacheDir', message: expect.stringContaining('top-level') }]);
  });

  it('rejects another bare root-level directory such as /var as cacheDir', () => {
    const issues = validateDefaults(defaults({ cacheDir: '/var' }));
    expect(issues).toEqual([{ field: 'cacheDir', message: expect.stringContaining('top-level') }]);
  });

  // --- allowOverrides: must be an array of recognized OverridableField members ---

  it('accepts a well-formed allowOverrides array', () => {
    expect(
      validateDefaults(defaults({ allowOverrides: ['severities', 'failOn'] })),
    ).toEqual([]);
  });

  it('accepts an empty allowOverrides array, meaning nothing may be overridden', () => {
    expect(validateDefaults(defaults({ allowOverrides: [] }))).toEqual([]);
  });

  it('rejects allowOverrides given as a string instead of an array', () => {
    const issues = validateDefaults(
      defaults({ allowOverrides: 'severities' as unknown as DefaultsConfig['allowOverrides'] }),
    );
    expect(issues).toEqual([
      { field: 'allowOverrides', message: expect.stringContaining('list') },
    ]);
  });

  it('rejects allowOverrides given as a plain object instead of an array', () => {
    const issues = validateDefaults(
      defaults({
        allowOverrides: { runner: true } as unknown as DefaultsConfig['allowOverrides'],
      }),
    );
    expect(issues).toEqual([
      { field: 'allowOverrides', message: expect.stringContaining('list') },
    ]);
  });

  it('rejects an allowOverrides element that is not an OverridableField, naming it', () => {
    const issues = validateDefaults(
      defaults({
        allowOverrides: ['severities', 'bogus'] as unknown as DefaultsConfig['allowOverrides'],
      }),
    );
    expect(issues).toEqual([
      { field: 'allowOverrides', message: expect.stringContaining('bogus') },
    ]);
  });

  // --- failOn: must be 'none' or a FailOn severity; UNKNOWN is deliberately excluded ---

  it('accepts failOn: none', () => {
    expect(validateDefaults(defaults({ failOn: 'none' }))).toEqual([]);
  });

  it('accepts failOn: CRITICAL', () => {
    expect(validateDefaults(defaults({ failOn: 'CRITICAL' }))).toEqual([]);
  });

  it('rejects a lowercase failOn value instead of silently resolving it downstream', () => {
    const issues = validateDefaults(
      defaults({ failOn: 'critical' as unknown as DefaultsConfig['failOn'] }),
    );
    expect(issues).toEqual([{ field: 'failOn', message: expect.stringContaining('failOn') }]);
  });

  it('rejects failOn: UNKNOWN and explains why, since it ranks lowest and would fail every build', () => {
    const issues = validateDefaults(
      defaults({ failOn: 'UNKNOWN' as unknown as DefaultsConfig['failOn'] }),
    );
    expect(issues).toEqual([
      {
        field: 'failOn',
        message: expect.stringContaining('UNKNOWN'),
      },
    ]);
    expect(issues[0].message.toLowerCase()).toContain('lowest');
  });

  // --- severities: every element must be a valid Severity, naming the offender ---

  it('rejects an invalid severity element, naming it, alongside a valid one', () => {
    const issues = validateDefaults(
      defaults({ severities: ['BOGUS', 'HIGH'] as unknown as Severity[] }),
    );
    expect(issues).toEqual([
      { field: 'severities', message: expect.stringContaining('BOGUS') },
    ]);
  });

  // --- scanners: every element must be a valid Scanner, naming the offender ---

  it('rejects an invalid scanner element, naming it, alongside a valid one', () => {
    const issues = validateDefaults(
      defaults({ scanners: ['vuln', 'bogus'] as unknown as Scanner[] }),
    );
    expect(issues).toEqual([
      { field: 'scanners', message: expect.stringContaining('bogus') },
    ]);
  });

  // --- dbRegistry credentials: administrator-entered pair, neither half may stand alone ---

  it('accepts defaults with neither db registry credential set', () => {
    expect(validateDefaults(defaults())).toEqual([]);
  });

  it('accepts defaults with both db registry credentials set', () => {
    expect(
      validateDefaults(defaults({ dbRegistryUsername: 'svc', dbRegistryPassword: 'p@ss' })),
    ).toEqual([]);
  });

  it('rejects a dbRegistryUsername without a dbRegistryPassword, naming the missing field', () => {
    const issues = validateDefaults(defaults({ dbRegistryUsername: 'svc' }));
    expect(issues).toEqual([
      { field: 'dbRegistryPassword', message: expect.stringContaining('dbRegistryPassword') },
    ]);
  });

  it('rejects a dbRegistryPassword without a dbRegistryUsername, naming the missing field', () => {
    const issues = validateDefaults(defaults({ dbRegistryPassword: 'p@ss' }));
    expect(issues).toEqual([
      { field: 'dbRegistryUsername', message: expect.stringContaining('dbRegistryUsername') },
    ]);
  });
});

describe('validateDatabase', () => {
  it('accepts a well-formed database', () => {
    expect(validateDatabase(database())).toEqual([]);
  });

  it('rejects an alias that is not lowercase kebab', () => {
    const issues = validateDatabase(database({ alias: 'Bad Alias' }));
    expect(issues).toEqual([{ field: 'alias', message: expect.stringContaining('lowercase') }]);
  });

  it('requires a repository', () => {
    const issues = validateDatabase(database({ repository: '' }));
    expect(issues).toEqual([{ field: 'repository', message: expect.stringContaining('required') }]);
  });

  it('rejects the latest tag on the repository because it is not reproducible', () => {
    const issues = validateDatabase(database({ repository: 'registry.example.com/trivy-db:latest' }));
    expect(issues).toEqual([{ field: 'repository', message: expect.stringContaining('latest') }]);
  });

  it('accepts a digest reference on the repository', () => {
    expect(
      validateDatabase(database({ repository: `registry.example.com/trivy-db@sha256:${'a'.repeat(64)}` })),
    ).toEqual([]);
  });

  it('accepts javaRepository omitted, since it is optional', () => {
    expect(validateDatabase(database())).toEqual([]);
  });

  it('rejects a javaRepository with a bad reference, under the same rule as repository', () => {
    const issues = validateDatabase(database({ javaRepository: 'registry.example.com/trivy-java-db:latest' }));
    expect(issues).toEqual([{ field: 'javaRepository', message: expect.stringContaining('latest') }]);
  });

  it('accepts a well-formed javaRepository', () => {
    expect(
      validateDatabase(database({ javaRepository: 'registry.example.com/trivy-java-db:1' })),
    ).toEqual([]);
  });

  // --- registry credentials: administrator-entered pair, neither half may stand alone ---

  it('accepts a database with neither registry credential set', () => {
    expect(validateDatabase(database())).toEqual([]);
  });

  it('accepts a database with both registry credentials set', () => {
    expect(
      validateDatabase(database({ registryUsername: 'svc', registryPassword: 'p@ss' })),
    ).toEqual([]);
  });

  it('rejects a registryUsername without a registryPassword, naming the missing field', () => {
    const issues = validateDatabase(database({ registryUsername: 'svc' }));
    expect(issues).toEqual([
      { field: 'registryPassword', message: expect.stringContaining('registryPassword') },
    ]);
  });

  it('rejects a registryPassword without a registryUsername, naming the missing field', () => {
    const issues = validateDatabase(database({ registryPassword: 'p@ss' }));
    expect(issues).toEqual([
      { field: 'registryUsername', message: expect.stringContaining('registryUsername') },
    ]);
  });

  it('rejects a non-object database instead of throwing', () => {
    expect(validateDatabase(null)).toEqual([{ field: 'database', message: expect.stringContaining('object') }]);
  });
});

describe('validateDatabaseCatalogue', () => {
  it('accepts a catalogue with unique aliases', () => {
    expect(validateDatabaseCatalogue([database(), database({ alias: 'hardened-db' })])).toEqual([]);
  });

  it('accepts an empty catalogue: there is no "default database" to require', () => {
    expect(validateDatabaseCatalogue([])).toEqual([]);
  });

  it('rejects duplicate aliases naming the duplicate', () => {
    const issues = validateDatabaseCatalogue([database(), database()]);
    expect(issues).toEqual([{ field: 'alias', message: expect.stringContaining('baseline-db') }]);
  });

  it('rejects a non-array catalogue instead of throwing', () => {
    expect(validateDatabaseCatalogue(null)).toEqual([
      { field: 'databases', message: expect.stringContaining('list of databases') },
    ]);
    expect(validateDatabaseCatalogue({})).toEqual([
      { field: 'databases', message: expect.stringContaining('list of databases') },
    ]);
  });

  it('rejects a non-object catalogue entry, naming its index, instead of dereferencing it', () => {
    const issues = validateDatabaseCatalogue([null, database()]);
    expect(issues).toEqual([{ field: 'databases[0]', message: expect.stringContaining('index 0') }]);
  });

  it('does not validate individual database fields, only cross-entry invariants', () => {
    expect(validateDatabaseCatalogue([{ alias: 'BAD', repository: 'x:latest' }])).toEqual([]);
  });
});

describe('validateRunnerDatabaseLinks', () => {
  const databases: DatabaseConfig[] = [database(), database({ alias: 'hardened-db' })];

  it('produces nothing for a runner with no database set, since it falls back to defaults', () => {
    expect(validateRunnerDatabaseLinks([runner()], databases)).toEqual([]);
  });

  it('produces nothing when a runner names a database alias that exists in the catalogue', () => {
    expect(validateRunnerDatabaseLinks([runner({ database: 'hardened-db' })], databases)).toEqual([]);
  });

  it('rejects a runner pointing at an unknown alias, listing the known ones', () => {
    const issues = validateRunnerDatabaseLinks([runner({ database: 'missing-db' })], databases);
    expect(issues).toEqual([
      {
        field: 'runners[0].database',
        message: expect.stringContaining('missing-db'),
      },
    ]);
    expect(issues[0].message).toContain('baseline-db');
    expect(issues[0].message).toContain('hardened-db');
  });

  it('reports no known databases distinctly when the catalogue is empty', () => {
    const issues = validateRunnerDatabaseLinks([runner({ database: 'missing-db' })], []);
    expect(issues).toEqual([
      {
        field: 'runners[0].database',
        message: expect.stringContaining('no databases are currently configured'),
      },
    ]);
  });

  it('rejects a runner naming an empty-string database, since that is a mistake rather than an omission', () => {
    const issues = validateRunnerDatabaseLinks([runner({ database: '' })], databases);
    expect(issues).toEqual([
      {
        field: 'runners[0].database',
        message: expect.stringContaining('empty string'),
      },
    ]);
  });

  it('rejects a non-array runners argument instead of throwing', () => {
    expect(validateRunnerDatabaseLinks(null, databases)).toEqual([
      { field: 'runners', message: expect.stringContaining('list of runners') },
    ]);
  });

  it('rejects a non-array databases argument instead of throwing', () => {
    expect(validateRunnerDatabaseLinks([runner()], null)).toEqual([
      { field: 'databases', message: expect.stringContaining('list of databases') },
    ]);
  });

  it('skips a non-object runner entry instead of throwing, leaving shape issues to validateCatalog', () => {
    expect(validateRunnerDatabaseLinks([null], databases)).toEqual([]);
  });
});
