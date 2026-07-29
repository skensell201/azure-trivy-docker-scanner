export type Severity = 'UNKNOWN' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type FailOn = Severity | 'none';
export type ScanType = 'image' | 'filesystem' | 'repository' | 'config' | 'sbom';
export type Scanner = 'vuln' | 'secret' | 'misconfig' | 'license';
export type OutputFormat = 'table' | 'json' | 'sarif';
export type SbomFormat = 'off' | 'cyclonedx' | 'spdx-json';
export type FindingKind = 'vulnerability' | 'secret' | 'misconfiguration' | 'license';

export type SeverityCounts = Record<Severity, number>;
export type KindCounts = Record<FindingKind, number>;

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
  /** Omitted means enabled. */
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
  /**
   * Omitted means every overridable field may be overridden by a task input;
   * an empty array means none may be. These are opposite meanings.
   */
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

/** The agent's runtime environment, known only once the task executes. */
export interface AgentContext {
  sourcesDir: string;
  agentHomeDir: string;
  tempDir: string;
  buildId: string;
}

/** Fully resolved configuration for a single run. Only genuinely optional fields remain optional. */
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
  /** Distinguishes several task instances in one job so their containers and report files do not collide. */
  scanIndex: number;
}

export interface Finding {
  kind: FindingKind;
  severity: Severity;
  /** Not unique within a report; the same CVE recurs once per affected target. */
  id: string;
  title: string;
  target: string;
  pkgName?: string;
  installedVersion?: string;
  fixedVersion?: string;
  /** Display only; the format is not stable enough to parse. */
  location?: string;
}

export interface RunnerInfo {
  alias: string;
  image: string;
  trivyVersion?: string;
  dbUpdatedAt?: string;
}

export interface NormalizedReport {
  /** Literal version of this normalized format, written by the task and read by the results tab. */
  schemaVersion: 1;
  scanType: ScanType;
  target: string;
  /** What Trivy reported it scanned, which can differ from the requested `target`. */
  artifactName: string;
  createdAt?: string;
  runner: RunnerInfo;
  findings: Finding[];
  counts: SeverityCounts;
  kindCounts: KindCounts;
}
