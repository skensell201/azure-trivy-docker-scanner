export type Severity = 'UNKNOWN' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type FailOn = Severity | 'none';
export type ScanType = 'image' | 'filesystem' | 'repository' | 'config' | 'sbom';
export type Scanner = 'vuln' | 'secret' | 'misconfig' | 'license';
export type OutputFormat = 'table' | 'json' | 'sarif';
export type SbomFormat = 'off' | 'cyclonedx' | 'spdx-json';
export type FindingKind = 'vulnerability' | 'secret' | 'misconfiguration' | 'license';

export type OverridableField =
  | 'runner'
  | 'severities'
  | 'scanners'
  | 'failOn'
  | 'ignoreUnfixed'
  | 'timeoutMinutes'
  | 'skipDbUpdate';

export interface RunnerConfig {
  alias: string;
  image: string;
  displayName?: string;
  description?: string;
  registryConnection?: string;
  extraDockerArgs?: string;
  isDefault?: boolean;
  enabled?: boolean;
}

export interface DefaultsConfig {
  dbRepository: string;
  javaDbRepository?: string;
  dbRegistryConnection?: string;
  cacheDir?: string;
  skipDbUpdate?: boolean;
  severities?: Severity[];
  scanners?: Scanner[];
  failOn?: FailOn;
  ignoreUnfixed?: boolean;
  timeoutMinutes?: number;
  allowOverrides?: OverridableField[];
}

export interface TaskInputs {
  scanType: ScanType;
  target: string;
  runner?: string;
  severities?: Severity[];
  scanners?: Scanner[];
  failOn?: FailOn;
  ignoreUnfixed?: boolean;
  ignoreFile?: string;
  timeoutMinutes?: number;
  skipDbUpdate?: boolean;
  targetRegistryConnection?: string;
  useDockerSocket?: boolean;
  formats?: OutputFormat[];
  generateSbom?: SbomFormat;
  publishArtifact?: boolean;
  extraTrivyArgs?: string;
  workingDirectory?: string;
}

/** Окружение агента, известное только в рантайме таска. */
export interface AgentContext {
  sourcesDir: string;
  agentHomeDir: string;
  tempDir: string;
  buildId: string;
}

/** Полностью определённая конфигурация одного запуска. Опциональны только реально необязательные поля. */
export interface ResolvedScanConfig {
  runner: RunnerConfig;
  scanType: ScanType;
  target: string;
  severities: Severity[];
  scanners: Scanner[];
  failOn: FailOn;
  ignoreUnfixed: boolean;
  skipDbUpdate: boolean;
  timeoutMinutes: number;
  dbRepository: string;
  javaDbRepository?: string;
  cacheDir: string;
  sourcesDir: string;
  workingDirectory?: string;
  ignoreFile?: string;
  useDockerSocket: boolean;
  formats: OutputFormat[];
  generateSbom: SbomFormat;
  publishArtifact: boolean;
  extraTrivyArgs?: string;
  buildId: string;
  scanIndex: number;
}

export interface Finding {
  kind: FindingKind;
  severity: Severity;
  id: string;
  title: string;
  target: string;
  pkgName?: string;
  installedVersion?: string;
  fixedVersion?: string;
  location?: string;
}

export interface RunnerInfo {
  alias: string;
  image: string;
  trivyVersion?: string;
  dbUpdatedAt?: string;
}

export interface NormalizedReport {
  schemaVersion: 1;
  scanType: ScanType;
  target: string;
  artifactName: string;
  createdAt?: string;
  runner: RunnerInfo;
  findings: Finding[];
  counts: Record<Severity, number>;
  kindCounts: Record<FindingKind, number>;
}
