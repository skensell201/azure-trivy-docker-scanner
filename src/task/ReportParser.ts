import { emptyKindCounts } from '../shared/findingKind';
import { emptySeverityCounts, isSeverity } from '../shared/severity';
import { Finding, NormalizedReport, RunnerInfo, ScanType, Severity } from '../shared/types';

export class TrivyReportParseError extends Error {}

export interface ReportMeta {
  scanType: ScanType;
  target: string;
  runner: RunnerInfo;
}

/**
 * `parseTrivyReport`'s return type, extended locally (rather than in shared/types.ts) so this
 * module can expose `unrecognizedSeverities` without other in-flight work on the shared types
 * file colliding with it. Structurally a superset of `NormalizedReport`, so every existing
 * consumer typed against that interface keeps working unchanged.
 */
export interface ParsedTrivyReport extends NormalizedReport {
  /**
   * Severity labels trivy reported that did not match the known vocabulary, degraded to
   * UNKNOWN in `findings` (see `toSeverity`). UNKNOWN ranks lowest and `FailOn` excludes it
   * as a threshold, so a finding degraded this way is structurally incapable of failing a
   * build — that must be visible to the caller instead of silently swallowed. Deduplicated,
   * sanitized (the label is attacker-influenced, same as any other trivy-reported text), and
   * empty when every severity was recognized.
   */
  unrecognizedSeverities: string[];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function toArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

/**
 * Trivy omits the "Results" key entirely when a scan finds nothing (confirmed against a real
 * 0.72.0 run against a repository with no lockfiles, secrets, or misconfigurations) rather than
 * emitting "Results": []. Before treating a Results-less document as "zero findings" instead of
 * "not a trivy report at all", this checks for fields trivy is known to always emit.
 *
 * `SchemaVersion` is trusted on its own: it is trivy's own version number for its *output*
 * schema (currently 2), present in every trivy report since that schema was introduced, and not
 * a field name another tool has a reason to coincidentally emit. `ArtifactName`/`ArtifactType`
 * are trusted only together, as a fallback for a hypothetical trivy schema that omits
 * SchemaVersion — neither is trusted alone, since either one in isolation is just an ordinary
 * string (or string-like) field that an unrelated JSON document could plausibly also have.
 */
function looksLikeTrivyReport(document: Record<string, unknown>): boolean {
  if (typeof document.SchemaVersion === 'number') {
    return true;
  }
  return typeof document.ArtifactName === 'string' && typeof document.ArtifactType === 'string';
}

// Long enough to show what actually arrived (a truncated field name, a stray character) without
// dumping an entire hostile or oversized payload into the build log.
const RAW_PREVIEW_MAX_CHARS = 200;

/**
 * Builds the message for a document rejected as "not recognizably a trivy report", covering
 * three distinct failure shapes: a non-object top-level value (null, array, primitive), an
 * object with a "Results" key that is present but not an array (malformed, not empty), and an
 * object with no marker fields at all. In every case the message names what was actually found
 * instead of only saying what was missing, since that is exactly the round trip this bug report
 * describes needing.
 *
 * Both the key list and the raw-text preview are attacker/publisher-controlled — a malformed or
 * hostile "trivy" image can put anything in its stdout, including object keys or raw bytes
 * containing an Azure Pipelines logging command (`##vso[...]`) that this message's own text
 * embeds directly into the build log. `sanitizeText` (shared with every trivy-controlled string
 * elsewhere in this module) strips control characters and collapses whitespace on both, so this
 * message cannot itself be used to inject a logging command.
 */
function rejectionMessage(document: unknown, raw: string, meta: ReportMeta): string {
  const keysNote = isRecord(document)
    ? Object.keys(document).length > 0
      ? sanitizeText(Object.keys(document).join(', '))
      : '(none)'
    : `not a JSON object (top-level value was ${
        document === null ? 'null' : Array.isArray(document) ? 'an array' : typeof document
      })`;
  const preview = sanitizeText(
    raw.length > RAW_PREVIEW_MAX_CHARS ? `${raw.slice(0, RAW_PREVIEW_MAX_CHARS)}…` : raw,
  );
  return (
    `Runner ${meta.runner.image} produced JSON without a "Results" array while scanning "${meta.target}". ` +
    `Check that the image really contains trivy. Top-level keys: ${keysNote}. ` +
    `Raw output (truncated): ${preview}`
  );
}

// eslint-disable-next-line no-control-regex -- intentional: strips C0 controls, DEL and NEL from trivy-reported text.
const CONTROL_CHARS = /[\x00-\x1f\x7f\u0085]/g;
const WHITESPACE_RUN = /\s+/g;

/**
 * Package names and versions in a filesystem/repository scan come straight out of scanned
 * lockfiles, so their content is controlled by whoever publishes a dependency. The Publisher
 * writes findings into Azure Pipelines logging commands that the agent parses line by line
 * from stdout, where a bare newline starts a new line and a line starting with `##vso[` is
 * executed as a command — a package name containing an embedded newline followed by
 * `##vso[task.complete result=Succeeded]` could mark a failed scan as passed. Replacing every
 * C0 control character (0x00-0x1F), DEL (0x7F) and NEL (U+0085 — a line-breaking control
 * character that JS's `\s` does not match on its own) with a space, then collapsing whitespace,
 * means every current and future consumer (log, JSON attachment, results tab) sees text that
 * cannot break its container, without truncating, stripping punctuation, or hiding the finding
 * itself. Accepts `unknown` because trivy's JSON is untrusted: a field declared as a string
 * can still arrive as a number or object from a malformed or hostile report, and coercing it
 * here is cheaper than validating the type at every call site.
 */
function sanitizeText(value: unknown): string {
  const text = typeof value === 'string' ? value : String(value);
  return text.replace(CONTROL_CHARS, ' ').replace(WHITESPACE_RUN, ' ').trim();
}

// Applied once to every finding regardless of kind, by iterating its own string-valued
// properties rather than a hand-written field list — so a future Finding field cannot
// silently skip sanitization the way a hand-written list would let it. `kind` and `severity`
// are excluded: both are our own validated enum values by this point (kind is a literal from
// this module, severity has already passed through toSeverity), never raw trivy text.
// Fields left absent by construction (fixedVersion with no fix, location on non-secret kinds)
// stay absent: only own-enumerable keys are visited, and undefined values are left untouched.
const ENUM_KEYS = new Set(['kind', 'severity']);

function sanitizeFinding(finding: Finding): Finding {
  const sanitized: Record<string, unknown> = { ...finding };
  for (const [key, value] of Object.entries(finding)) {
    if (ENUM_KEYS.has(key) || value === undefined) {
      continue;
    }
    sanitized[key] = sanitizeText(value);
  }
  return sanitized as unknown as Finding;
}

// Trivy's own output is not our data format and may gain values over time; a scan that
// produced results should not be discarded because of one odd severity label. This is the
// opposite of shared/severity.ts, where an unknown severity is an error: config is ours to
// validate, trivy's output is not. Accepts `unknown` because a malformed report can put
// anything in the Severity field (a number, an object); anything that is not a recognized
// string degrades the same way. Unrecognized, defined labels are recorded (sanitized, since
// they are attacker-influenced) so the caller can warn that a scan produced findings that
// cannot fail the build.
function toSeverity(raw: unknown, unrecognized: Set<string>): Severity {
  if (raw === undefined) {
    return 'UNKNOWN';
  }
  const label = typeof raw === 'string' ? raw : String(raw);
  const upper = label.toUpperCase();
  if (isSeverity(upper)) {
    return upper;
  }
  unrecognized.add(sanitizeText(label));
  return 'UNKNOWN';
}

export function parseTrivyReport(raw: string, meta: ReportMeta): ParsedTrivyReport {
  let document: unknown;
  try {
    document = JSON.parse(raw);
  } catch (error) {
    throw new TrivyReportParseError(
      `Runner ${meta.runner.image} produced output that is not valid JSON while scanning "${meta.target}": ${
        (error as Error).message
      }`,
    );
  }

  // A bare `null`, a top-level array, or any other non-object document all fail this check
  // before anything tries to read a `.Results` property off them — the same TypeError a
  // `null` entry inside `Results` would otherwise cause below.
  //
  // Three ways a document can supply its findings array:
  //   - `Results` present and an array: use it as-is (the common case).
  //   - `Results` absent, but the document is otherwise recognisable as trivy output
  //     (`looksLikeTrivyReport`): treat it as zero findings — trivy's own behavior for a scan
  //     that found nothing, see that function's comment for why this is trusted.
  //   - Anything else — `Results` present but not an array (malformed, not empty), or no marker
  //     field recognisable at all — is rejected. Both stay hard errors: a runner image that
  //     isn't really trivy is a real failure mode and must stay diagnosable, and a `Results` key
  //     of the wrong type is a sign of corruption, not an empty scan.
  let results: unknown[];
  if (isRecord(document) && Array.isArray(document.Results)) {
    results = document.Results;
  } else if (isRecord(document) && document.Results === undefined && looksLikeTrivyReport(document)) {
    results = [];
  } else {
    throw new TrivyReportParseError(rejectionMessage(document, raw, meta));
  }

  const unrecognizedSeverities = new Set<string>();
  const rawFindings: Finding[] = [];

  for (const rawResult of results) {
    // A malformed entry (null, a string, a number) contributes no findings rather than
    // taking down the whole parse, the same way one unrecognized severity does not.
    const result = isRecord(rawResult) ? rawResult : {};
    const target = typeof result.Target === 'string' ? result.Target : meta.target;

    for (const rawItem of toArray(result.Vulnerabilities)) {
      const item = isRecord(rawItem) ? rawItem : {};
      rawFindings.push({
        kind: 'vulnerability',
        severity: toSeverity(item.Severity, unrecognizedSeverities),
        id: (item.VulnerabilityID ?? 'UNKNOWN') as string,
        title: (item.Title ?? item.VulnerabilityID ?? 'Unknown vulnerability') as string,
        target,
        pkgName: item.PkgName as string | undefined,
        installedVersion: item.InstalledVersion as string | undefined,
        // Omitted rather than set to undefined: trivy frequently has no fix yet, and an
        // absent key reads cleaner than `fixedVersion: undefined` wherever this gets serialized.
        ...(item.FixedVersion ? { fixedVersion: item.FixedVersion as string } : {}),
      });
    }

    for (const rawItem of toArray(result.Secrets)) {
      const item = isRecord(rawItem) ? rawItem : {};
      // A truthy check on StartLine would treat line 0 as absent and fall back to the bare
      // target; checking the type instead keeps a legitimate line 0 in the location.
      const hasStartLine = typeof item.StartLine === 'number';
      rawFindings.push({
        kind: 'secret',
        severity: toSeverity(item.Severity, unrecognizedSeverities),
        id: (item.RuleID ?? 'UNKNOWN') as string,
        title: (item.Title ?? item.RuleID ?? 'Unknown secret') as string,
        target,
        location: hasStartLine ? `${target}:${item.StartLine}` : target,
      });
    }

    // Only failing checks become findings: trivy also reports the checks that passed,
    // and counting those would make every build red.
    for (const rawItem of toArray(result.Misconfigurations)) {
      const item = isRecord(rawItem) ? rawItem : {};
      if (item.Status !== 'FAIL') {
        continue;
      }
      rawFindings.push({
        kind: 'misconfiguration',
        severity: toSeverity(item.Severity, unrecognizedSeverities),
        id: (item.ID ?? 'UNKNOWN') as string,
        title: (item.Title ?? item.ID ?? 'Unknown misconfiguration') as string,
        target,
      });
    }

    for (const rawItem of toArray(result.Licenses)) {
      const item = isRecord(rawItem) ? rawItem : {};
      rawFindings.push({
        kind: 'license',
        severity: toSeverity(item.Severity, unrecognizedSeverities),
        id: (item.Name ?? 'UNKNOWN') as string,
        title: `${(item.Category as string | undefined) ?? 'license'}: ${(item.Name as string | undefined) ?? 'unknown'}`,
        target,
        pkgName: item.PkgName as string | undefined,
      });
    }
  }

  const findings = rawFindings.map(sanitizeFinding);

  const counts = emptySeverityCounts();
  const kindCounts = emptyKindCounts();

  for (const finding of findings) {
    counts[finding.severity] += 1;
    kindCounts[finding.kind] += 1;
  }

  return {
    schemaVersion: 1,
    scanType: meta.scanType,
    target: meta.target,
    artifactName: sanitizeText(document.ArtifactName ?? meta.target),
    createdAt: document.CreatedAt !== undefined ? sanitizeText(document.CreatedAt) : undefined,
    runner: meta.runner,
    findings,
    counts,
    kindCounts,
    unrecognizedSeverities: [...unrecognizedSeverities],
  };
}

// The version probe is decoration: losing the trivy version or the database timestamp
// must not fail a scan that otherwise worked. Its output still reaches the Publisher's own
// log-line sanitizer, which assumes a string, so non-string values are coerced and control
// characters normalized here rather than left for that sanitizer to crash on.
export function parseVersion(raw: string): { trivyVersion?: string; dbUpdatedAt?: string } {
  try {
    const document = JSON.parse(raw) as {
      Version?: unknown;
      VulnerabilityDB?: { UpdatedAt?: unknown };
    };
    return {
      ...(document.Version !== undefined && document.Version !== null
        ? { trivyVersion: sanitizeText(document.Version) }
        : {}),
      ...(document.VulnerabilityDB?.UpdatedAt !== undefined && document.VulnerabilityDB?.UpdatedAt !== null
        ? { dbUpdatedAt: sanitizeText(document.VulnerabilityDB.UpdatedAt) }
        : {}),
    };
  } catch {
    return {};
  }
}
