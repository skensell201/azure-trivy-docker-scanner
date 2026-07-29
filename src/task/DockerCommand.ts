import * as path from 'path';
import { splitArgs } from '../shared/args';
import { ResolvedScanConfig } from '../shared/types';

const WORKSPACE = '/workspace';
const CACHE_MOUNT = '/root/.cache/trivy';

export interface RegistryCredentials {
  username?: string;
  password?: string;
}

export function containerName(config: ResolvedScanConfig): string {
  return `trivyscan-${config.buildId}-${config.scanIndex}`;
}

export function containerReportPath(config: ResolvedScanConfig): string {
  return `${WORKSPACE}/.trivy/report-${config.scanIndex}.json`;
}

export function hostReportPath(config: ResolvedScanConfig): string {
  return path.posix.join(config.sourcesDir, '.trivy', `report-${config.scanIndex}.json`);
}

export function buildScanArgs(config: ResolvedScanConfig, envFilePath: string): string[] {
  const docker = [
    'run',
    '--rm',
    '--name',
    containerName(config),
    '--env-file',
    envFilePath,
    '-v',
    `${config.cacheDir}:${CACHE_MOUNT}`,
    '-v',
    `${config.sourcesDir}:${WORKSPACE}`,
    '-w',
    config.workingDirectory ? path.posix.join(WORKSPACE, config.workingDirectory) : WORKSPACE,
  ];

  if (config.useDockerSocket) {
    docker.push('-v', '/var/run/docker.sock:/var/run/docker.sock');
  }

  docker.push(...splitArgs(config.runner.extraDockerArgs), config.runner.image);

  const trivy = [
    config.scanType,
    '--format',
    'json',
    '--output',
    containerReportPath(config),
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
    trivy.push('--ignorefile', path.posix.join(WORKSPACE, config.ignoreFile));
  }

  trivy.push(...splitArgs(config.extraTrivyArgs), config.target);

  return [...docker, ...trivy];
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
