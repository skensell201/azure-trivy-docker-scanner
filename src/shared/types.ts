export type Severity = 'UNKNOWN' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
/**
 * The severity threshold at which the build gate fails, or 'none' to disable it.
 * Deliberately excludes 'UNKNOWN': since UNKNOWN ranks below every other severity,
 * allowing it as a threshold would make `failOn: 'UNKNOWN'` the *strictest* possible
 * setting (failing on every finding, including the ones trivy could not score) — the
 * opposite of what an administrator reading "UNKNOWN" in a dropdown would expect.
 * UNKNOWN remains a perfectly valid *finding* severity; it is only meaningless as a
 * threshold.
 */
export type FailOn = Exclude<Severity, 'UNKNOWN'> | 'none';
export type ScanType = 'image' | 'filesystem' | 'repository' | 'config' | 'sbom';
export type Scanner = 'vuln' | 'secret' | 'misconfig' | 'license';
export type OutputFormat = 'table' | 'json' | 'sarif';
export type SbomFormat = 'off' | 'cyclonedx' | 'spdx-json';
export type FindingKind = 'vulnerability' | 'secret' | 'misconfiguration' | 'license';
/**
 * How the sources reach the scan container. 'mount' (default) bind-mounts sourcesDir with
 * `docker run -v`, which the docker daemon resolves itself and therefore requires the
 * daemon to share a filesystem with the agent. 'copy' instead streams the sources in and
 * the report back out over the docker API (`docker cp`), so it works even when the agent
 * runs in a container whose docker daemon is reached through a mounted socket and cannot
 * see the agent's own filesystem at all. See DockerCommand.ts and run.ts for the mechanics
 * and the costs (no cache mount, sources streamed on every scan).
 */
export type SourceTransfer = 'mount' | 'copy';

export type SeverityCounts = Record<Severity, number>;
export type KindCounts = Record<FindingKind, number>;

export type OverridableField =
  | 'runner'
  | 'severities'
  | 'scanners'
  | 'failOn'
  | 'ignoreUnfixed'
  | 'timeoutMinutes'
  | 'skipDbUpdate'
  | 'useDockerSocket'
  | 'extraTrivyArgs'
  | 'ignoreFile';

export interface RunnerConfig {
  alias: string;
  image: string;
  displayName?: string;
  description?: string;
  /**
   * Entered once by an administrator in the settings document, not supplied per pipeline:
   * the Extension Data Service is not a secret store, so `registryPassword` is stored in
   * plain text and readable by anyone with extension-data read access to this collection. Both
   * fields are optional together, but `validateRunner` rejects one being set without the other.
   */
  registryUsername?: string;
  registryPassword?: string;
  extraDockerArgs?: string;
  isDefault?: boolean;
  /** Omitted means enabled. */
  enabled?: boolean;
}

export interface DefaultsConfig {
  dbRepository: string;
  javaDbRepository?: string;
  /**
   * Same plain-text-storage caveat as `RunnerConfig.registryUsername`/`registryPassword`
   * above. Trivy reads these from `TRIVY_USERNAME`/`TRIVY_PASSWORD` inside the container,
   * which the scanned image's own credentials (`TaskInputs.targetRegistryConnection`) also
   * use - see `run.ts`'s credential resolution for how that collision is handled.
   */
  dbRegistryUsername?: string;
  dbRegistryPassword?: string;
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
  /**
   * Not an `OverridableField`, for the same reason `publishArtifact` above is not one:
   * `allowOverrides` exists to protect the *integrity* of the scan and its gate (a pipeline
   * author must not be able to weaken `severities`, `failOn`, or slip in `extraTrivyArgs` to
   * quietly defeat them). Publishing every finding as a JUnit test result changes nothing
   * about the scan, the gate, or which findings exist -- it only adds a second, opt-in *view*
   * onto results the gate has already evaluated. There is no integrity reason for a collection
   * administrator to forbid a pipeline from turning on a reporting convenience, so -- like
   * `formats`, `generateSbom` and `publishArtifact` -- any pipeline may always set it directly.
   */
  publishTestResults?: boolean;
  extraTrivyArgs?: string;
  workingDirectory?: string;
  /**
   * Not an `OverridableField`: it describes this agent's own topology (does its docker
   * daemon share a filesystem with it?), not a security policy an administrator would
   * ever want to lock a pipeline out of. Unlike weakening `severities` or `failOn`, there
   * is no gate-integrity reason to restrict it centrally, and a collection can easily mix
   * agent pools with different topologies -- so, like `formats` or `workingDirectory`, any
   * pipeline may always set it directly.
   */
  sourceTransfer?: SourceTransfer;
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
  publishTestResults: boolean;
  extraTrivyArgs?: string;
  buildId: string;
  /** Distinguishes several task instances in one job so their containers and report files do not collide. */
  scanIndex: number;
  sourceTransfer: SourceTransfer;
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
