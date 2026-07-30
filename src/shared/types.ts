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
  /**
   * The alias of this runner's entry in the database catalogue (`DatabaseConfig[]`), so a
   * runner backed by a custom trivy image can bring its own vulnerability database instead of
   * assuming the collection-wide one. Optional only for compatibility with a settings document
   * written before the catalogue existed, not because leaving it unset is good configuration:
   * a runner with no `database` falls back to the deprecated `dbRepository`/`javaDbRepository`/
   * `dbRegistryUsername`/`dbRegistryPassword` fields on `DefaultsConfig`, and the task warns
   * when it does so. New configurations should always set this explicitly.
   */
  database?: string;
}

/**
 * A single entry in the database catalogue: a named, reusable vulnerability database that one
 * or more runners can point at by alias (`RunnerConfig.database`). The catalogue itself is
 * stored as its own settings document, alongside `runners` and `defaults` -- a database is a
 * property of the runner that uses it, not a collection-wide setting, since a runner backed by
 * a custom trivy image may ship with, and expect, its own database rather than the official
 * one. There is no "default database": a runner names one explicitly, or falls back to
 * `DefaultsConfig`'s deprecated fields (see `RunnerConfig.database`'s doc comment).
 */
export interface DatabaseConfig {
  alias: string;
  repository: string;
  javaRepository?: string;
  /**
   * Same plain-text-storage caveat as `RunnerConfig.registryUsername`/`registryPassword`:
   * entered once by an administrator, not supplied per pipeline. Both fields are optional
   * together, but `validateDatabase` rejects one being set without the other.
   */
  registryUsername?: string;
  registryPassword?: string;
  displayName?: string;
  description?: string;
}

export interface DefaultsConfig {
  /**
   * @deprecated Pre-catalogue arrangement, from before a database was a per-runner
   * concept (see `DatabaseConfig`/`RunnerConfig.database`). Still honoured as the
   * fallback for a runner with no `database` set, so it is not removed, but it is no
   * longer where a new configuration should record its database: that belongs in the
   * catalogue, linked to a runner by alias. Will be removed once configurations have
   * moved. Was formerly the one required field of `DefaultsConfig` -- a fully migrated
   * configuration has no database settings in `defaults` at all, so it is optional now;
   * the equivalent "is a database actually configured" check has moved to the catalogue
   * (`validateDatabaseCatalogue`) and the runner-to-database link
   * (`validateRunnerDatabaseLinks`), not disappeared.
   */
  dbRepository?: string;
  /** @deprecated Same pre-catalogue arrangement as `dbRepository` above; see its doc comment. */
  javaDbRepository?: string;
  /**
   * Same plain-text-storage caveat as `RunnerConfig.registryUsername`/`registryPassword`
   * above. Trivy reads these from `TRIVY_USERNAME`/`TRIVY_PASSWORD` inside the container,
   * which the scanned image's own credentials (`TaskInputs.targetRegistryConnection`) also
   * use - see `run.ts`'s credential resolution for how that collision is handled.
   *
   * @deprecated Same pre-catalogue arrangement as `dbRepository` above; see its doc
   * comment. A cataloged `DatabaseConfig` carries its own `registryUsername`/
   * `registryPassword` instead.
   */
  dbRegistryUsername?: string;
  /** @deprecated Same pre-catalogue arrangement as `dbRepository` above; see its doc comment. */
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
