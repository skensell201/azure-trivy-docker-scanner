import { compareSeverity, emptySeverityCounts, isAtLeast, SEVERITY_ORDER } from '../shared/severity';
import { emptyKindCounts } from '../shared/findingKind';
import { FailOn, Finding, KindCounts, NormalizedReport, SeverityCounts } from '../shared/types';

export type GateOutcome = 'succeeded' | 'succeededWithIssues' | 'failed';

export interface GateResult {
  outcome: GateOutcome;
  /** One-line human summary. Never carries per-kind detail: callers that need that render `blockingKindCounts` themselves. */
  reason: string;
  /**
   * The findings that crossed the threshold, sorted from most to least severe.
   * Callers (the build summary and the results tab) only render a prefix of this
   * list, so report order — whatever trivy happened to emit — would silently hide
   * the worst findings behind a wall of lower-severity ones.
   */
  blocking: Finding[];
  /** The failOn value this evaluation was run against, including 'none'. */
  threshold: FailOn;
  /** Per-severity counts of `blocking` only — not of the whole report. */
  blockingCounts: SeverityCounts;
  /**
   * Per-kind counts of `blocking` only. A CRITICAL leaked secret and a CRITICAL
   * vulnerability demand different responses (rotate a credential vs. bump a
   * package); this is how a caller tells them apart without parsing `reason`.
   */
  blockingKindCounts: KindCounts;
}

function sortBySeverityDescending(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => compareSeverity(b.severity, a.severity));
}

function countBySeverity(findings: Finding[]): SeverityCounts {
  const counts = emptySeverityCounts();
  findings.forEach((finding) => {
    counts[finding.severity] += 1;
  });
  return counts;
}

function countByKind(findings: Finding[]): KindCounts {
  const counts = emptyKindCounts();
  findings.forEach((finding) => {
    counts[finding.kind] += 1;
  });
  return counts;
}

function pluralize(count: number, noun: string): string {
  return `${count} ${count === 1 ? noun : `${noun}s`}`;
}

export function evaluateGate(report: NormalizedReport, failOn: FailOn): GateResult {
  // 'none' is not a Severity, and isAtLeast throws on values outside the vocabulary,
  // so this early return is load-bearing: it is what makes an unconditional pass possible.
  if (failOn === 'none') {
    const total = report.findings.length;
    return {
      outcome: 'succeeded',
      reason:
        total === 0
          ? 'No findings, the gate is disabled (failOn: none)'
          : `${pluralize(total, 'finding')} reported, the gate is disabled (failOn: none)`,
      // Disabled means disabled: nothing blocks, or the entry point's
      // `if (gate.blocking.length > 0) publisher.logBlockingFindings(...)` would log
      // every finding in the report as a build issue despite the gate being off.
      blocking: [],
      threshold: failOn,
      blockingCounts: emptySeverityCounts(),
      blockingKindCounts: emptyKindCounts(),
    };
  }

  // isAtLeast ranks UNKNOWN below every other severity, and FailOn can no longer be
  // 'UNKNOWN', so an UNKNOWN-severity finding never meets any real threshold. This is
  // a deliberate default: trivy could not score the finding, which is not the same as
  // it being minor, but until a threshold narrower than LOW exists there is nothing
  // else a gate could do with it.
  const blocking = sortBySeverityDescending(
    report.findings.filter((finding) => isAtLeast(finding.severity, failOn)),
  );

  if (blocking.length === 0) {
    if (report.findings.length === 0) {
      return {
        outcome: 'succeeded',
        reason: 'No findings',
        blocking: [],
        threshold: failOn,
        blockingCounts: emptySeverityCounts(),
        blockingKindCounts: emptyKindCounts(),
      };
    }
    return {
      outcome: 'succeededWithIssues',
      reason: `${pluralize(report.findings.length, 'finding')} below the failOn threshold ${failOn}`,
      blocking: [],
      threshold: failOn,
      blockingCounts: emptySeverityCounts(),
      blockingKindCounts: emptyKindCounts(),
    };
  }

  const blockingCounts = countBySeverity(blocking);

  const breakdown = [...SEVERITY_ORDER]
    .reverse()
    .map((severity) => ({ severity, count: blockingCounts[severity] }))
    .filter((entry) => entry.count > 0)
    .map((entry) => `${entry.count} ${entry.severity}`)
    .join(', ');

  return {
    outcome: 'failed',
    reason: `${breakdown} at or above the failOn threshold ${failOn} (${pluralize(report.findings.length, 'finding')} total)`,
    blocking,
    threshold: failOn,
    blockingCounts,
    blockingKindCounts: countByKind(blocking),
  };
}
