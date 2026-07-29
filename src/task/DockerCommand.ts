import * as path from 'path';
import { splitArgs } from '../shared/args';
import { ResolvedScanConfig } from '../shared/types';

const WORKSPACE = '/workspace';
const CACHE_MOUNT = '/root/.cache/trivy';

export interface RegistryCredentials {
  username?: string;
  password?: string;
}

/**
 * Trivy flags that this module already sets to values the report parser and
 * the build gate depend on, or that correspond to a specific policy-gated
 * `TaskInputs` field. `extraTrivyArgs` may not set any of these directly: on
 * a cobra CLI the last occurrence of a scalar flag wins, so letting the
 * pipeline write one of these would let it silently override behavior the
 * task, or an administrator's `allowOverrides` policy, already decided.
 * Exported so other layers (e.g. the admin UI) can reuse the same list.
 */
export const RESERVED_TRIVY_FLAGS: readonly string[] = [
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
];

const RESERVED_FLAG_GUIDANCE: Record<string, string> = {
  '--format': 'the report format is fixed so the parser can read it back; there is no input for it',
  '-f': 'the report format is fixed so the parser can read it back; there is no input for it',
  '--output':
    'the report destination is fixed so the task can read the file back; there is no input for it',
  '-o': 'the report destination is fixed so the task can read the file back; there is no input for it',
  '--exit-code':
    "the build gate is computed from the parsed report, not trivy's exit code; there is no input for it",
  '--severity': 'set the "severities" input instead',
  '-s': 'set the "severities" input instead',
  '--scanners': 'set the "scanners" input instead',
  '--ignore-unfixed': 'set the "ignoreUnfixed" input instead',
  '--skip-db-update': 'set the "skipDbUpdate" input instead',
  '--ignorefile': 'set the "ignoreFile" input instead',
  '--timeout': 'set the "timeoutMinutes" input instead',
};

/**
 * Rejects rather than silently drops a reserved flag: silently ignoring
 * what someone wrote is worse UX than a clear refusal that names the flag
 * and the input that actually controls it. Handles both `--flag value`
 * (two tokens) and `--flag=value` (one token) spellings.
 */
function assertNoReservedTrivyFlags(tokens: readonly string[]): void {
  for (const token of tokens) {
    const flag = token.includes('=') ? token.slice(0, token.indexOf('=')) : token;
    if (RESERVED_TRIVY_FLAGS.includes(flag)) {
      throw new Error(`extraTrivyArgs may not set "${flag}": ${RESERVED_FLAG_GUIDANCE[flag]}.`);
    }
  }
}

/** SARIF and, separately, SBOM (cyclonedx or spdx-json) are extra runs of the same runner image. */
export type ExtraFormat = 'sarif' | 'cyclonedx' | 'spdx-json';

export function containerName(config: ResolvedScanConfig, suffix = ''): string {
  return `trivyscan-${config.buildId}-${config.scanIndex}${suffix ? `-${suffix}` : ''}`;
}

export function containerReportPath(config: ResolvedScanConfig): string {
  return `${WORKSPACE}/.trivy/report-${config.scanIndex}.json`;
}

export function hostReportPath(config: ResolvedScanConfig): string {
  return path.posix.join(config.sourcesDir, '.trivy', `report-${config.scanIndex}.json`);
}

/** sarif keeps the "report" name (it is one more shape of the same report); cyclonedx and
 * spdx-json share the "sbom" name since generateSbom is a single field - only one of them
 * ever runs for a given scan, so there is no naming collision to worry about between them. */
function extraFileName(format: ExtraFormat, scanIndex: number): string {
  return format === 'sarif' ? `report-${scanIndex}.sarif` : `sbom-${scanIndex}.json`;
}

function containerExtraPath(config: ResolvedScanConfig, format: ExtraFormat): string {
  return `${WORKSPACE}/.trivy/${extraFileName(format, config.scanIndex)}`;
}

export function hostExtraPath(config: ResolvedScanConfig, format: ExtraFormat): string {
  return path.posix.join(config.sourcesDir, '.trivy', extraFileName(format, config.scanIndex));
}

/**
 * Joins a relative path onto the workspace mount and rejects the result if
 * it normalizes to somewhere outside `/workspace`. Clamping a `..` escape
 * silently (e.g. treating it as staying at the mount root) would hide the
 * mistake: a filesystem scan with a relative target would then silently
 * scan the runner image instead of the checked-out sources and could pass
 * the gate with zero findings. Rejecting surfaces the mistake instead of
 * turning it into a false negative.
 */
function resolveWithinWorkspace(
  relative: string,
  field: 'workingDirectory' | 'ignoreFile',
): string {
  const resolved = path.posix.join(WORKSPACE, relative);
  if (resolved !== WORKSPACE && !resolved.startsWith(`${WORKSPACE}/`)) {
    throw new Error(
      `"${field}" value "${relative}" escapes the mounted workspace (resolves to "${resolved}"). ` +
        'Use a path relative to the sources root.',
    );
  }
  return resolved;
}

export function buildScanArgs(config: ResolvedScanConfig, envFilePath: string): string[] {
  return buildArgs(config, envFilePath, 'json', containerReportPath(config), '');
}

/**
 * SARIF and SBOM are additional runs of the same runner image against the same target,
 * differing only in --format/--output and in the container name suffix that keeps them
 * from clashing with the JSON scan or each other. Going through buildArgs means every
 * protection the JSON run gets - the reserved-flag check, the workspace-escape checks on
 * workingDirectory/ignoreFile, and the re-assertion of --format/--output/--exit-code
 * after extraTrivyArgs - applies here too, parameterized on this run's own format and
 * output path rather than a hardcoded 'json'.
 */
export function buildFormatArgs(
  config: ResolvedScanConfig,
  envFilePath: string,
  format: ExtraFormat,
): string[] {
  return buildArgs(
    config,
    envFilePath,
    format,
    containerExtraPath(config, format),
    format === 'sarif' ? 'sarif' : 'sbom',
  );
}

function buildArgs(
  config: ResolvedScanConfig,
  envFilePath: string,
  format: string,
  containerOutput: string,
  nameSuffix: string,
): string[] {
  const extraTrivyTokens = splitArgs(config.extraTrivyArgs);
  assertNoReservedTrivyFlags(extraTrivyTokens);

  const docker = [
    'run',
    '--rm',
    '--name',
    containerName(config, nameSuffix),
    '--env-file',
    envFilePath,
    '-v',
    `${config.cacheDir}:${CACHE_MOUNT}`,
    '-v',
    `${config.sourcesDir}:${WORKSPACE}`,
    '-w',
    config.workingDirectory
      ? resolveWithinWorkspace(config.workingDirectory, 'workingDirectory')
      : WORKSPACE,
  ];

  if (config.useDockerSocket) {
    docker.push('-v', '/var/run/docker.sock:/var/run/docker.sock');
  }

  // extraDockerArgs is administrator-only - TaskInputs carries no such field,
  // so a pipeline cannot reach it - and the same administrator already
  // chooses RunnerConfig.image, so they can run arbitrary code on the agent
  // through the image alone regardless. It is deliberately left unrestricted
  // here rather than guarded by a deny-list that could not add real safety.
  docker.push(...splitArgs(config.runner.extraDockerArgs), config.runner.image);

  const trivy = [
    config.scanType,
    '--format',
    format,
    '--output',
    containerOutput,
    '--exit-code',
    '0',
    '--severity',
    config.severities.join(','),
  ];

  // trivy config has no --scanners flag: it always runs the misconfiguration scanner.
  if (config.scanType !== 'config') {
    trivy.push('--scanners', config.scanners.join(','));
  }

  if (config.ignoreUnfixed) {
    trivy.push('--ignore-unfixed');
  }
  if (config.skipDbUpdate) {
    trivy.push('--skip-db-update');
  }

  trivy.push('--timeout', `${config.timeoutMinutes}m`);

  if (config.ignoreFile) {
    trivy.push('--ignorefile', resolveWithinWorkspace(config.ignoreFile, 'ignoreFile'));
  }

  trivy.push(
    ...extraTrivyTokens,
    // Re-assert after extraTrivyArgs: on a cobra CLI the last occurrence of a
    // scalar flag wins, so whatever the pipeline wrote must not be allowed to
    // win over the flags the parser and the gate depend on. Uses this run's own
    // format/containerOutput, not a literal - a SARIF run re-asserts sarif and its
    // own output path, not json's.
    // RESERVED_TRIVY_FLAGS above should make this unreachable in practice -
    // this is the actual enforcement, and the reserved-flag check is the
    // friendlier error message standing in front of it.
    '--format',
    format,
    '--output',
    containerOutput,
    '--exit-code',
    '0',
    config.target,
  );

  return [...docker, ...trivy];
}

/** Docker's own default when an image reference names no registry at all. */
const DOCKER_HUB_HOST = 'docker.io';

/**
 * Derives the registry host that a `docker pull`/`docker login` for this image would talk
 * to, following the standard rule docker itself uses to parse a reference: the segment
 * before the first `/` is the registry host only if it looks like one (contains a `.` or a
 * `:`, the latter covering an explicit port); otherwise the whole reference is a Docker Hub
 * name (with or without a `library/`-style implicit namespace) and the host is Docker Hub's
 * own default. A `@sha256:` digest does not change this: the digest marker always comes
 * after the first `/`, if any, so it never participates in this decision.
 */
export function registryHostFromImage(image: string): string {
  const firstSlash = image.indexOf('/');
  if (firstSlash === -1) {
    return DOCKER_HUB_HOST;
  }
  const firstSegment = image.slice(0, firstSlash);
  if (firstSegment.includes('.') || firstSegment.includes(':')) {
    return firstSegment;
  }
  return DOCKER_HUB_HOST;
}

/**
 * `docker login <host> --username <user> --password-stdin` for the registry that hosts a
 * runner's image. The password is deliberately not a parameter here: it must reach docker
 * only through `RunOptions.stdin` (see ProcessRunner), never through argv, where it would be
 * visible in `ps` on the agent and in any debug log that echoes the command.
 */
export function buildLoginArgs(host: string, username: string): string[] {
  return ['login', host, '--username', username, '--password-stdin'];
}

export function buildVersionArgs(config: ResolvedScanConfig): string[] {
  return [
    'run',
    '--rm',
    '-v',
    `${config.cacheDir}:${CACHE_MOUNT}`,
    config.runner.image,
    'version',
    '--format',
    'json',
  ];
}

export function buildTrivyEnv(
  config: ResolvedScanConfig,
  credentials: RegistryCredentials,
): Record<string, string> {
  const env: Record<string, string> = {
    TRIVY_DB_REPOSITORY: config.dbRepository,
    TRIVY_CACHE_DIR: CACHE_MOUNT,
    TRIVY_NO_PROGRESS: 'true',
  };

  if (config.javaDbRepository) {
    env.TRIVY_JAVA_DB_REPOSITORY = config.javaDbRepository;
  }
  if (credentials.username) {
    env.TRIVY_USERNAME = credentials.username;
  }
  if (credentials.password) {
    env.TRIVY_PASSWORD = credentials.password;
  }

  return env;
}
