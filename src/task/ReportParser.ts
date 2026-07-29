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

  const findings: Finding[] = [];

  for (const result of document.Results) {
    const target = result.Target ?? meta.target;

    for (const item of result.Vulnerabilities ?? []) {
      findings.push({
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
      findings.push({
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
      findings.push({
        kind: 'misconfiguration',
        severity: toSeverity(item.Severity),
        id: item.ID ?? 'UNKNOWN',
        title: item.Title ?? item.ID ?? 'Unknown misconfiguration',
        target,
      });
    }

    for (const item of result.Licenses ?? []) {
      findings.push({
        kind: 'license',
        severity: toSeverity(item.Severity),
        id: item.Name ?? 'UNKNOWN',
        title: `${item.Category ?? 'license'}: ${item.Name ?? 'unknown'}`,
        target,
        pkgName: item.PkgName,
      });
    }
  }

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
