import { emptyKindCounts } from '../shared/findingKind';
import { emptySeverityCounts, isSeverity } from '../shared/severity';
import { Finding, NormalizedReport, RunnerInfo, ScanType, Severity } from '../shared/types';

export class TrivyReportParseError extends Error {}

export interface ReportMeta {
  scanType: ScanType;
  target: string;
  runner: RunnerInfo;
}

interface RawResult {
  Target?: string;
  Vulnerabilities?: RawVulnerability[];
  Secrets?: RawSecret[];
  Misconfigurations?: RawMisconfiguration[];
  Licenses?: RawLicense[];
}

interface RawVulnerability {
  VulnerabilityID?: string;
  PkgName?: string;
  InstalledVersion?: string;
  FixedVersion?: string;
  Severity?: string;
  Title?: string;
}

interface RawSecret {
  RuleID?: string;
  Title?: string;
  Severity?: string;
  StartLine?: number;
}

interface RawMisconfiguration {
  ID?: string;
  Title?: string;
  Severity?: string;
  Status?: string;
}

interface RawLicense {
  Name?: string;
  PkgName?: string;
  Severity?: string;
  Category?: string;
}

// Trivy's own output is not our data format and may gain values over time; a scan that
// produced results should not be discarded because of one odd severity label. This is the
// opposite of shared/severity.ts, where an unknown severity is an error: config is ours to
// validate, trivy's output is not.
function toSeverity(raw: string | undefined): Severity {
  const value = (raw ?? '').toUpperCase();
  return isSeverity(value) ? value : 'UNKNOWN';
}

const CONTROL_CHARS = /[\r\n\t]/g;
const WHITESPACE_RUN = /\s+/g;

/**
 * Package names and versions in a filesystem/repository scan come straight out of scanned
 * lockfiles, so their content is controlled by whoever publishes a dependency. The Publisher
 * writes findings into Azure Pipelines logging commands that the agent parses line by line
 * from stdout, where a bare newline starts a new line and a line starting with `##vso[` is
 * executed as a command — a package name containing an embedded newline followed by
 * `##vso[task.complete result=Succeeded]` could mark a failed scan as passed. Replacing CR/LF/
 * tab and collapsing whitespace here, once, means every current and future consumer (log, JSON
 * attachment, results tab) sees text that cannot break its container, without truncating,
 * stripping punctuation, or hiding the finding itself.
 */
function sanitizeText(value: string): string {
  return value.replace(CONTROL_CHARS, ' ').replace(WHITESPACE_RUN, ' ').trim();
}

// Applied once to every finding regardless of kind, so a future finding kind cannot forget it.
// Fields left absent by the construction above (fixedVersion with no fix, location on
// non-secret kinds) stay absent: the conditional spreads only touch fields that are present.
function sanitizeFinding(finding: Finding): Finding {
  return {
    ...finding,
    id: sanitizeText(finding.id),
    title: sanitizeText(finding.title),
    target: sanitizeText(finding.target),
    ...(finding.pkgName !== undefined ? { pkgName: sanitizeText(finding.pkgName) } : {}),
    ...(finding.installedVersion !== undefined
      ? { installedVersion: sanitizeText(finding.installedVersion) }
      : {}),
    ...(finding.fixedVersion !== undefined ? { fixedVersion: sanitizeText(finding.fixedVersion) } : {}),
    ...(finding.location !== undefined ? { location: sanitizeText(finding.location) } : {}),
  };
}

export function parseTrivyReport(raw: string, meta: ReportMeta): NormalizedReport {
  let document: { Results?: RawResult[]; ArtifactName?: string; CreatedAt?: string };
  try {
    document = JSON.parse(raw);
  } catch (error) {
    throw new TrivyReportParseError(
      `Runner ${meta.runner.image} produced output that is not valid JSON while scanning "${meta.target}": ${
        (error as Error).message
      }`,
    );
  }

  if (!Array.isArray(document.Results)) {
    throw new TrivyReportParseError(
      `Runner ${meta.runner.image} produced JSON without a "Results" array while scanning "${meta.target}". Check that the image really contains trivy.`,
    );
  }

  const rawFindings: Finding[] = [];

  for (const result of document.Results) {
    const target = result.Target ?? meta.target;

    for (const item of result.Vulnerabilities ?? []) {
      rawFindings.push({
        kind: 'vulnerability',
        severity: toSeverity(item.Severity),
        id: item.VulnerabilityID ?? 'UNKNOWN',
        title: item.Title ?? item.VulnerabilityID ?? 'Unknown vulnerability',
        target,
        pkgName: item.PkgName,
        installedVersion: item.InstalledVersion,
        // Omitted rather than set to undefined: trivy frequently has no fix yet, and an
        // absent key reads cleaner than `fixedVersion: undefined` wherever this gets serialized.
        ...(item.FixedVersion ? { fixedVersion: item.FixedVersion } : {}),
      });
    }

    for (const item of result.Secrets ?? []) {
      rawFindings.push({
        kind: 'secret',
        severity: toSeverity(item.Severity),
        id: item.RuleID ?? 'UNKNOWN',
        title: item.Title ?? item.RuleID ?? 'Unknown secret',
        target,
        location: item.StartLine ? `${target}:${item.StartLine}` : target,
      });
    }

    // Only failing checks become findings: trivy also reports the checks that passed,
    // and counting those would make every build red.
    for (const item of result.Misconfigurations ?? []) {
      if (item.Status !== 'FAIL') {
        continue;
      }
      rawFindings.push({
        kind: 'misconfiguration',
        severity: toSeverity(item.Severity),
        id: item.ID ?? 'UNKNOWN',
        title: item.Title ?? item.ID ?? 'Unknown misconfiguration',
        target,
      });
    }

    for (const item of result.Licenses ?? []) {
      rawFindings.push({
        kind: 'license',
        severity: toSeverity(item.Severity),
        id: item.Name ?? 'UNKNOWN',
        title: `${item.Category ?? 'license'}: ${item.Name ?? 'unknown'}`,
        target,
        pkgName: item.PkgName,
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
    artifactName: document.ArtifactName ?? meta.target,
    createdAt: document.CreatedAt,
    runner: meta.runner,
    findings,
    counts,
    kindCounts,
  };
}

// The version probe is decoration: losing the trivy version or the database timestamp
// must not fail a scan that otherwise worked.
export function parseVersion(raw: string): { trivyVersion?: string; dbUpdatedAt?: string } {
  try {
    const document = JSON.parse(raw) as {
      Version?: string;
      VulnerabilityDB?: { UpdatedAt?: string };
    };
    return {
      ...(document.Version ? { trivyVersion: document.Version } : {}),
      ...(document.VulnerabilityDB?.UpdatedAt ? { dbUpdatedAt: document.VulnerabilityDB.UpdatedAt } : {}),
    };
  } catch {
    return {};
  }
}
