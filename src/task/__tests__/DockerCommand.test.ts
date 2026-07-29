import {
  buildScanArgs,
  buildVersionArgs,
  buildTrivyEnv,
  containerReportPath,
  hostReportPath,
} from '../DockerCommand';
import { ResolvedScanConfig } from '../../shared/types';

const config = (over: Partial<ResolvedScanConfig> = {}): ResolvedScanConfig => ({
  runner: { alias: 'baseline', image: 'reg.corp/trivy:0.58.1' },
  scanType: 'image',
  target: 'app:1.4.2',
  severities: ['CRITICAL', 'HIGH'],
  scanners: ['vuln', 'secret'],
  failOn: 'CRITICAL',
  ignoreUnfixed: false,
  skipDbUpdate: false,
  timeoutMinutes: 10,
  dbRepository: 'reg.corp/trivy-db:2',
  cacheDir: '/agent/_trivy-cache',
  sourcesDir: '/agent/_work/1/s',
  useDockerSocket: false,
  formats: ['table', 'json'],
  generateSbom: 'off',
  publishArtifact: true,
  buildId: '1042',
  scanIndex: 0,
  ...over,
});

describe('buildScanArgs', () => {
  it('mounts the cache and the sources and runs the runner image', () => {
    const args = buildScanArgs(config(), '/tmp/trivy.env');
    expect(args).toEqual([
      'run',
      '--rm',
      '--name',
      'trivyscan-1042-0',
      '--env-file',
      '/tmp/trivy.env',
      '-v',
      '/agent/_trivy-cache:/root/.cache/trivy',
      '-v',
      '/agent/_work/1/s:/workspace',
      '-w',
      '/workspace',
      'reg.corp/trivy:0.58.1',
      'image',
      '--format',
      'json',
      '--output',
      '/workspace/.trivy/report-0.json',
      '--exit-code',
      '0',
      '--severity',
      'CRITICAL,HIGH',
      '--scanners',
      'vuln,secret',
      '--timeout',
      '10m',
      'app:1.4.2',
    ]);
  });

  it('never places a secret in argv', () => {
    const args = buildScanArgs(config(), '/tmp/trivy.env');
    expect(args.join(' ')).not.toMatch(/password|token/i);
  });

  it('mounts the docker socket only when asked', () => {
    expect(buildScanArgs(config(), '/tmp/e').join(' ')).not.toContain('docker.sock');
    expect(buildScanArgs(config({ useDockerSocket: true }), '/tmp/e')).toContain(
      '/var/run/docker.sock:/var/run/docker.sock',
    );
  });

  it('inserts extra docker args before the image and extra trivy args after the flags', () => {
    const args = buildScanArgs(
      config({
        runner: { alias: 'baseline', image: 'reg.corp/trivy:0.58.1', extraDockerArgs: '--network none' },
        extraTrivyArgs: '--offline-scan',
      }),
      '/tmp/e',
    );
    expect(args.indexOf('--network')).toBeLessThan(args.indexOf('reg.corp/trivy:0.58.1'));
    expect(args.indexOf('--offline-scan')).toBeGreaterThan(args.indexOf('--timeout'));
    expect(args[args.length - 1]).toBe('app:1.4.2');
  });

  it('adds ignore-unfixed and skip-db-update flags when enabled', () => {
    const args = buildScanArgs(config({ ignoreUnfixed: true, skipDbUpdate: true }), '/tmp/e');
    expect(args).toContain('--ignore-unfixed');
    expect(args).toContain('--skip-db-update');
  });

  it('passes the ignore file through its container path', () => {
    const args = buildScanArgs(config({ ignoreFile: '.trivyignore' }), '/tmp/e');
    expect(args.slice(args.indexOf('--ignorefile'), args.indexOf('--ignorefile') + 2)).toEqual([
      '--ignorefile',
      '/workspace/.trivyignore',
    ]);
  });

  it('omits the scanners flag for a config scan because trivy config rejects it', () => {
    const args = buildScanArgs(config({ scanType: 'config', target: './infra' }), '/tmp/e');
    expect(args).not.toContain('--scanners');
    expect(args[args.length - 1]).toBe('./infra');
  });

  it('gives each scan in a build its own container name and report file', () => {
    const args = buildScanArgs(config({ scanIndex: 3 }), '/tmp/e');
    expect(args).toContain('trivyscan-1042-3');
    expect(args).toContain('/workspace/.trivy/report-3.json');
  });

  // The host needs to read the report back after the container exits. A
  // `workingDirectory` containing ".." changes the container's `-w`, but the
  // report path is computed independently of it, so it always stays under
  // the mounted workspace regardless of what workingDirectory does to `-w`.
  it('keeps the report output path under the workspace mount even when workingDirectory escapes it', () => {
    const args = buildScanArgs(config({ workingDirectory: '../../etc' }), '/tmp/e');
    expect(args).toContain('/workspace/.trivy/report-0.json');
    expect(containerReportPath(config({ workingDirectory: '../../etc' }))).toBe(
      '/workspace/.trivy/report-0.json',
    );
  });

  // extraTrivyArgs is appended after our own flags precisely so a later
  // occurrence cannot win the cobra "last flag wins" race against
  // --severity/--scanners, and the scan target must remain the final
  // positional argument no matter what else is configured.
  it('places --severity and --scanners strictly before extraTrivyArgs, with the target genuinely last', () => {
    const args = buildScanArgs(
      config({ ignoreFile: '.trivyignore', extraTrivyArgs: '--offline-scan' }),
      '/tmp/e',
    );
    expect(args.indexOf('--severity')).toBeLessThan(args.indexOf('--offline-scan'));
    expect(args.indexOf('--scanners')).toBeLessThan(args.indexOf('--offline-scan'));
    expect(args[args.length - 1]).toBe(config().target);
  });
});

describe('buildVersionArgs', () => {
  it('asks the runner image for its trivy and database version as json', () => {
    expect(buildVersionArgs(config())).toEqual([
      'run',
      '--rm',
      '-v',
      '/agent/_trivy-cache:/root/.cache/trivy',
      'reg.corp/trivy:0.58.1',
      'version',
      '--format',
      'json',
    ]);
  });
});

describe('buildTrivyEnv', () => {
  it('points trivy at the internal database mirror and cache', () => {
    expect(buildTrivyEnv(config(), {})).toMatchObject({
      TRIVY_DB_REPOSITORY: 'reg.corp/trivy-db:2',
      TRIVY_CACHE_DIR: '/root/.cache/trivy',
      TRIVY_NO_PROGRESS: 'true',
    });
  });

  it('includes the java database mirror only when configured', () => {
    expect(buildTrivyEnv(config(), {})).not.toHaveProperty('TRIVY_JAVA_DB_REPOSITORY');
    expect(
      buildTrivyEnv(config({ javaDbRepository: 'reg.corp/trivy-java-db:1' }), {}),
    ).toMatchObject({ TRIVY_JAVA_DB_REPOSITORY: 'reg.corp/trivy-java-db:1' });
  });

  it('carries registry credentials for the scanned image', () => {
    expect(buildTrivyEnv(config(), { username: 'svc', password: 'p@ss' })).toMatchObject({
      TRIVY_USERNAME: 'svc',
      TRIVY_PASSWORD: 'p@ss',
    });
  });

  // A `docker run --env-file` line is KEY=value, split on the first "=":
  // an "=" inside the value is safe and must survive untouched. A newline
  // is genuinely unrepresentable in that format, but rejecting it is the
  // env-file writer's job (a later task), not this builder's.
  it('preserves an equals sign inside a credential value', () => {
    expect(buildTrivyEnv(config(), { password: 'p@ss=word' })).toMatchObject({
      TRIVY_PASSWORD: 'p@ss=word',
    });
  });
});

describe('report paths', () => {
  it('maps the container report path onto the host workspace', () => {
    expect(containerReportPath(config({ scanIndex: 1 }))).toBe('/workspace/.trivy/report-1.json');
    expect(hostReportPath(config({ scanIndex: 1 }))).toBe(
      '/agent/_work/1/s/.trivy/report-1.json',
    );
  });
});
