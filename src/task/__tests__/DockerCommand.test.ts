import {
  buildCopyInArgs,
  buildCopyOutArgs,
  buildFormatArgs,
  buildLoginArgs,
  buildRemoveArgs,
  buildScanArgs,
  buildStartArgs,
  buildVersionArgs,
  buildTrivyEnv,
  containerExtraPath,
  containerReportPath,
  extraNameSuffix,
  hostExtraPath,
  hostReportPath,
  registryHostFromImage,
  RESERVED_TRIVY_FLAGS,
} from '../DockerCommand';
import { ResolvedScanConfig } from '../../shared/types';

const config = (over: Partial<ResolvedScanConfig> = {}): ResolvedScanConfig => ({
  runner: { alias: 'baseline', image: 'registry.example.com/trivy:0.58.1' },
  scanType: 'image',
  target: 'app:1.4.2',
  severities: ['CRITICAL', 'HIGH'],
  scanners: ['vuln', 'secret'],
  failOn: 'CRITICAL',
  ignoreUnfixed: false,
  skipDbUpdate: false,
  timeoutMinutes: 10,
  dbRepository: 'registry.example.com/trivy-db:2',
  cacheDir: '/agent/_trivy-cache',
  sourcesDir: '/agent/_work/1/s',
  useDockerSocket: false,
  formats: ['table', 'json'],
  generateSbom: 'off',
  publishArtifact: true,
  buildId: '1042',
  scanIndex: 0,
  sourceTransfer: 'mount',
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
      'registry.example.com/trivy:0.58.1',
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
      // Re-asserted after extraTrivyArgs (empty here) so a pipeline can never
      // move these three flags: see the "re-asserts" test below.
      '--format',
      'json',
      '--output',
      '/workspace/.trivy/report-0.json',
      '--exit-code',
      '0',
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
        runner: { alias: 'baseline', image: 'registry.example.com/trivy:0.58.1', extraDockerArgs: '--network none' },
        extraTrivyArgs: '--offline-scan',
      }),
      '/tmp/e',
    );
    expect(args.indexOf('--network')).toBeLessThan(args.indexOf('registry.example.com/trivy:0.58.1'));
    expect(args.indexOf('--offline-scan')).toBeGreaterThan(args.indexOf('--timeout'));
    expect(args[args.length - 1]).toBe('app:1.4.2');
  });

  // extraDockerArgs is reachable only by an administrator (TaskInputs carries
  // no such field), and that same administrator already chooses the runner
  // image, so it is deliberately left unrestricted here - contrast with the
  // reserved-flag rejection applied to extraTrivyArgs below, which IS
  // pipeline-reachable.
  it('passes extraDockerArgs through unrestricted, since it is administrator-only', () => {
    const args = buildScanArgs(
      config({
        runner: { alias: 'baseline', image: 'registry.example.com/trivy:0.58.1', extraDockerArgs: '--privileged' },
      }),
      '/tmp/e',
    );
    expect(args).toContain('--privileged');
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

  it('nests the working directory under the workspace mount', () => {
    const args = buildScanArgs(config({ workingDirectory: 'subdir' }), '/tmp/e');
    expect(args[args.indexOf('-w') + 1]).toBe('/workspace/subdir');
  });

  // The report path is computed from containerReportPath/hostReportPath,
  // which never look at workingDirectory at all, so the host can always read
  // the report back regardless of which (non-escaping) working directory a
  // scan uses. An escaping workingDirectory is rejected outright instead of
  // reaching this far - see the rejection test below.
  it('keeps the report output path under the workspace mount independent of workingDirectory', () => {
    const args = buildScanArgs(config({ workingDirectory: 'subdir' }), '/tmp/e');
    expect(args).toContain('/workspace/.trivy/report-0.json');
    expect(containerReportPath(config({ workingDirectory: 'subdir' }))).toBe(
      '/workspace/.trivy/report-0.json',
    );
  });

  // Silently clamping a ".." escape would hide the mistake: a filesystem scan
  // with a relative target would then silently scan the runner image instead
  // of the checked-out sources and could pass the gate with zero findings.
  it('rejects a workingDirectory that escapes the mounted workspace', () => {
    expect(() => buildScanArgs(config({ workingDirectory: '../../etc' }), '/tmp/e')).toThrow(
      /workingDirectory.*escapes/is,
    );
  });

  it('rejects an ignoreFile that escapes the mounted workspace', () => {
    expect(() =>
      buildScanArgs(config({ ignoreFile: '../../../etc/passwd' }), '/tmp/e'),
    ).toThrow(/ignoreFile.*escapes/is);
  });

  // Ordering alone offers no protection here: appending extraTrivyArgs after
  // our own flags is exactly what lets a later, user-supplied occurrence win
  // cobra's "last flag wins" scalar-flag race. --severity/--scanners are
  // actually the two flags this ordering protects least, since trivy treats
  // them as accumulating flags rather than last-write-wins scalars. What
  // actually protects the machine-critical flags is the reserved-flag
  // rejection plus re-asserting --format/--output/--exit-code after
  // extraTrivyArgs (see the tests below). The only guarantee this test pins
  // is that the scan target remains the final positional argument.
  it('places --severity and --scanners strictly before extraTrivyArgs, with the target genuinely last', () => {
    const args = buildScanArgs(
      config({ ignoreFile: '.trivyignore', extraTrivyArgs: '--offline-scan' }),
      '/tmp/e',
    );
    expect(args.indexOf('--severity')).toBeLessThan(args.indexOf('--offline-scan'));
    expect(args.indexOf('--scanners')).toBeLessThan(args.indexOf('--offline-scan'));
    expect(args[args.length - 1]).toBe(config().target);
  });

  it('re-asserts --format, --output and --exit-code after extraTrivyArgs so they cannot be overridden', () => {
    const args = buildScanArgs(config({ extraTrivyArgs: '--offline-scan' }), '/tmp/e');
    expect(args[args.length - 1]).toBe('app:1.4.2');
    expect(args.slice(args.length - 7, args.length - 1)).toEqual([
      '--format',
      'json',
      '--output',
      '/workspace/.trivy/report-0.json',
      '--exit-code',
      '0',
    ]);
  });

  it('always sets --exit-code to 0 so the gate is computed by us, not by trivy', () => {
    const args = buildScanArgs(config(), '/tmp/e');
    expect(args[args.indexOf('--exit-code') + 1]).toBe('0');
  });

  it('always requests --format json so the parser can read the report', () => {
    const args = buildScanArgs(config(), '/tmp/e');
    expect(args[args.indexOf('--format') + 1]).toBe('json');
  });
});

describe('extraTrivyArgs reserved flags', () => {
  it('lists exactly the flags this builder already controls', () => {
    expect(RESERVED_TRIVY_FLAGS).toEqual([
      '--format',
      '-f',
      '--output',
      '-o',
      '--exit-code',
      '--severity',
      '-s',
      '--scanners',
      '--ignore-unfixed',
      '--skip-db-update',
      '--ignorefile',
      '--timeout',
    ]);
  });

  it.each(RESERVED_TRIVY_FLAGS)('refuses "%s value" in extraTrivyArgs', (flag) => {
    expect(() => buildScanArgs(config({ extraTrivyArgs: `${flag} something` }), '/tmp/e')).toThrow();
  });

  it.each(RESERVED_TRIVY_FLAGS)('refuses "%s=value" in extraTrivyArgs', (flag) => {
    expect(() => buildScanArgs(config({ extraTrivyArgs: `${flag}=something` }), '/tmp/e')).toThrow();
  });

  it('names the offending flag and points at the input that controls it', () => {
    expect(() => buildScanArgs(config({ extraTrivyArgs: '--severity LOW' }), '/tmp/e')).toThrow(
      /--severity.*severities/s,
    );
  });

  it('lets an unreserved flag through', () => {
    expect(() => buildScanArgs(config({ extraTrivyArgs: '--offline-scan' }), '/tmp/e')).not.toThrow();
  });
});

describe('buildVersionArgs', () => {
  it('asks the runner image for its trivy and database version as json', () => {
    expect(buildVersionArgs(config())).toEqual([
      'run',
      '--rm',
      '-v',
      '/agent/_trivy-cache:/root/.cache/trivy',
      'registry.example.com/trivy:0.58.1',
      'version',
      '--format',
      'json',
    ]);
  });

  // The cache mount would be exactly as silently-empty in copy mode as the sources mount
  // this feature exists to fix -- there is no shared filesystem with the daemon in this
  // mode, so claiming a cache hit the probe cannot actually have would be misleading.
  it('drops the cache mount in copy mode', () => {
    expect(buildVersionArgs(config({ sourceTransfer: 'copy' }))).toEqual([
      'run',
      '--rm',
      'registry.example.com/trivy:0.58.1',
      'version',
      '--format',
      'json',
    ]);
  });
});

describe('buildTrivyEnv', () => {
  it('points trivy at the internal database mirror and cache', () => {
    expect(buildTrivyEnv(config(), {})).toMatchObject({
      TRIVY_DB_REPOSITORY: 'registry.example.com/trivy-db:2',
      TRIVY_CACHE_DIR: '/root/.cache/trivy',
      TRIVY_NO_PROGRESS: 'true',
    });
  });

  it('includes the java database mirror only when configured', () => {
    expect(buildTrivyEnv(config(), {})).not.toHaveProperty('TRIVY_JAVA_DB_REPOSITORY');
    expect(
      buildTrivyEnv(config({ javaDbRepository: 'registry.example.com/trivy-java-db:1' }), {}),
    ).toMatchObject({ TRIVY_JAVA_DB_REPOSITORY: 'registry.example.com/trivy-java-db:1' });
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

describe('registryHostFromImage', () => {
  it('uses the first path segment as the host when it contains a dot', () => {
    expect(registryHostFromImage('registry.example.com/trivy:0.58.1')).toBe('registry.example.com');
  });

  it('uses the first path segment as the host when it contains a port (colon)', () => {
    expect(registryHostFromImage('registry.example.com:5000/trivy:0.58.1')).toBe('registry.example.com:5000');
  });

  it('falls back to Docker Hub for a bare image name with no registry segment', () => {
    expect(registryHostFromImage('nginx:1.25')).toBe('docker.io');
  });

  it('falls back to Docker Hub when the first path segment has neither a dot nor a colon', () => {
    expect(registryHostFromImage('library/nginx:1.25')).toBe('docker.io');
  });

  it('handles a digest reference the same way as a tagged one', () => {
    expect(registryHostFromImage(`registry.example.com/trivy@sha256:${'a'.repeat(64)}`)).toBe('registry.example.com');
  });
});

describe('buildLoginArgs', () => {
  it('builds a docker login command for the host and username, reading the password from stdin', () => {
    expect(buildLoginArgs('registry.example.com', 'svc')).toEqual([
      'login',
      'registry.example.com',
      '--username',
      'svc',
      '--password-stdin',
    ]);
  });

  it('never places the password in the argv it returns', () => {
    const args = buildLoginArgs('registry.example.com', 'svc');
    expect(args.join(' ')).not.toMatch(/p@ss|password(?!-stdin)/i);
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

describe('buildFormatArgs', () => {
  it('reuses the scan command with a different format and output', () => {
    const args = buildFormatArgs(config(), '/tmp/e', 'sarif');
    expect(args.slice(args.indexOf('--format'), args.indexOf('--format') + 2)).toEqual([
      '--format',
      'sarif',
    ]);
    expect(args).toContain('/workspace/.trivy/report-0.sarif');
    expect(args[args.length - 1]).toBe('app:1.4.2');
  });

  it('gives the extra run its own container name so it cannot clash with the scan', () => {
    const args = buildFormatArgs(config(), '/tmp/e', 'sarif');
    expect(args).toContain('trivyscan-1042-0-sarif');
    expect(args).not.toContain('trivyscan-1042-0');
  });

  it('names the sbom output after the sbom format and gives it a container name distinct from sarif', () => {
    const cyclonedx = buildFormatArgs(config(), '/tmp/e', 'cyclonedx');
    expect(cyclonedx).toContain('/workspace/.trivy/sbom-0.json');
    expect(cyclonedx).toContain('trivyscan-1042-0-sbom');

    const spdx = buildFormatArgs(config(), '/tmp/e', 'spdx-json');
    expect(spdx).toContain('/workspace/.trivy/sbom-0.json');
    expect(spdx[spdx.indexOf('--format') + 1]).toBe('spdx-json');
  });

  it('maps extra outputs onto host paths', () => {
    expect(hostExtraPath(config(), 'sarif')).toBe('/agent/_work/1/s/.trivy/report-0.sarif');
    expect(hostExtraPath(config(), 'spdx-json')).toBe('/agent/_work/1/s/.trivy/sbom-0.json');
  });

  it('gives an extra run for a different scanIndex its own container name and output file', () => {
    const args = buildFormatArgs(config({ scanIndex: 3 }), '/tmp/e', 'sarif');
    expect(args).toContain('trivyscan-1042-3-sarif');
    expect(args).toContain('/workspace/.trivy/report-3.sarif');
  });

  // The plan's illustrative snippet re-asserts a hardcoded '--format json' after
  // extraTrivyArgs; that would be wrong for an extra-format run, which must re-assert
  // its OWN format and output. This pins that buildFormatArgs shares the real
  // enforcement, parameterized correctly, rather than copying buildScanArgs's literal.
  it("re-asserts its own format and output after extraTrivyArgs, not a hardcoded 'json'", () => {
    const args = buildFormatArgs(config({ extraTrivyArgs: '--offline-scan' }), '/tmp/e', 'sarif');
    expect(args[args.length - 1]).toBe('app:1.4.2');
    expect(args.slice(args.length - 7, args.length - 1)).toEqual([
      '--format',
      'sarif',
      '--output',
      '/workspace/.trivy/report-0.sarif',
      '--exit-code',
      '0',
    ]);
  });

  it.each(RESERVED_TRIVY_FLAGS)(
    'rejects the reserved flag "%s" in extraTrivyArgs for an extra-format run too',
    (flag) => {
      expect(() =>
        buildFormatArgs(config({ extraTrivyArgs: `${flag} value` }), '/tmp/e', 'sarif'),
      ).toThrow();
    },
  );

  it('mounts the docker socket for an extra run only when asked, same as the scan', () => {
    expect(buildFormatArgs(config(), '/tmp/e', 'sarif').join(' ')).not.toContain('docker.sock');
    expect(buildFormatArgs(config({ useDockerSocket: true }), '/tmp/e', 'sarif')).toContain(
      '/var/run/docker.sock:/var/run/docker.sock',
    );
  });

  it('rejects a workingDirectory that escapes the workspace for an extra run too', () => {
    expect(() =>
      buildFormatArgs(config({ workingDirectory: '../../etc' }), '/tmp/e', 'sarif'),
    ).toThrow(/workingDirectory.*escapes/is);
  });
});

describe('sourceTransfer: copy', () => {
  const copyConfig = (over: Partial<ResolvedScanConfig> = {}) =>
    config({ sourceTransfer: 'copy', ...over });

  it('creates the container instead of running it, and drops --rm', () => {
    const args = buildScanArgs(copyConfig(), '/tmp/trivy.env');
    expect(args[0]).toBe('create');
    expect(args).not.toContain('run');
    expect(args).not.toContain('--rm');
  });

  it('never mounts the sources directory or the cache directory', () => {
    const args = buildScanArgs(copyConfig(), '/tmp/trivy.env').join(' ');
    expect(args).not.toContain('/agent/_work/1/s:/workspace');
    expect(args).not.toContain('/agent/_trivy-cache:/root/.cache/trivy');
    expect(args).not.toContain('-v');
  });

  it('still names the container, passes the env file and sets the working directory', () => {
    const args = buildScanArgs(copyConfig(), '/tmp/trivy.env');
    expect(args).toEqual([
      'create',
      '--name',
      'trivyscan-1042-0',
      '--env-file',
      '/tmp/trivy.env',
      '-w',
      '/workspace',
      'registry.example.com/trivy:0.58.1',
      'image',
      '--format',
      'json',
      '--output',
      '/tmp/report-0.json',
      '--exit-code',
      '0',
      '--severity',
      'CRITICAL,HIGH',
      '--scanners',
      'vuln,secret',
      '--timeout',
      '10m',
      '--format',
      'json',
      '--output',
      '/tmp/report-0.json',
      '--exit-code',
      '0',
      'app:1.4.2',
    ]);
  });

  it('still mounts the docker socket when asked, since it is not a sources/cache path', () => {
    expect(
      buildScanArgs(copyConfig({ useDockerSocket: true }), '/tmp/e'),
    ).toContain('/var/run/docker.sock:/var/run/docker.sock');
  });

  it('nests the working directory under the workspace the same way as mount mode', () => {
    const args = buildScanArgs(copyConfig({ workingDirectory: 'subdir' }), '/tmp/e');
    expect(args[args.indexOf('-w') + 1]).toBe('/workspace/subdir');
  });

  it('writes the report flat under /tmp, not under /workspace/.trivy', () => {
    expect(containerReportPath(copyConfig())).toBe('/tmp/report-0.json');
    expect(containerReportPath(copyConfig({ scanIndex: 2 }))).toBe('/tmp/report-2.json');
  });

  it('writes extra-format outputs flat under /tmp too', () => {
    expect(containerExtraPath(copyConfig(), 'sarif')).toBe('/tmp/report-0.sarif');
    expect(containerExtraPath(copyConfig(), 'cyclonedx')).toBe('/tmp/sbom-0.json');
  });

  it('leaves the host-side report and extra-output paths unchanged from mount mode', () => {
    expect(hostReportPath(copyConfig())).toBe('/agent/_work/1/s/.trivy/report-0.json');
    expect(hostExtraPath(copyConfig(), 'sarif')).toBe('/agent/_work/1/s/.trivy/report-0.sarif');
  });

  it('creates the extra-format run with its own container name, in create form too', () => {
    const args = buildFormatArgs(copyConfig(), '/tmp/e', 'sarif');
    expect(args[0]).toBe('create');
    expect(args).toContain('trivyscan-1042-0-sarif');
    expect(args).not.toContain('-v');
    expect(args).toContain('/tmp/report-0.sarif');
  });

  it('mount mode is unaffected by the existence of copy mode', () => {
    // Byte-for-byte pin: switching sourceTransfer to 'copy' and back must not have
    // perturbed the 'mount' construction path at all.
    const args = buildScanArgs(config(), '/tmp/trivy.env');
    expect(args[0]).toBe('run');
    expect(args).toContain('--rm');
    expect(args).toContain('/agent/_work/1/s:/workspace');
    expect(args).toContain('/agent/_trivy-cache:/root/.cache/trivy');
  });
});

describe('extraNameSuffix', () => {
  it('names sarif runs "sarif" and both sbom formats "sbom"', () => {
    expect(extraNameSuffix('sarif')).toBe('sarif');
    expect(extraNameSuffix('cyclonedx')).toBe('sbom');
    expect(extraNameSuffix('spdx-json')).toBe('sbom');
  });
});

describe('copy-mode step builders', () => {
  it('buildCopyInArgs copies the host sources directory onto the container workspace', () => {
    expect(buildCopyInArgs('/agent/_work/1/s', 'trivyscan-1042-0')).toEqual([
      'cp',
      '/agent/_work/1/s',
      'trivyscan-1042-0:/workspace',
    ]);
  });

  it('buildStartArgs attaches so the exit code and output stream through', () => {
    expect(buildStartArgs('trivyscan-1042-0')).toEqual(['start', '-a', 'trivyscan-1042-0']);
  });

  it('buildCopyOutArgs copies a container path back onto a host path', () => {
    expect(buildCopyOutArgs('trivyscan-1042-0', '/tmp/report-0.json', '/agent/_work/1/s/.trivy/report-0.json')).toEqual([
      'cp',
      'trivyscan-1042-0:/tmp/report-0.json',
      '/agent/_work/1/s/.trivy/report-0.json',
    ]);
  });

  it('buildRemoveArgs force-removes the named container', () => {
    expect(buildRemoveArgs('trivyscan-1042-0')).toEqual(['rm', '-f', 'trivyscan-1042-0']);
  });
});
