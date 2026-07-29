import { isAtLeast, SEVERITY_ORDER } from '../shared/severity';
import { FailOn, Finding, NormalizedReport } from '../shared/types';

export type GateOutcome = 'succeeded' | 'succeededWithIssues' | 'failed';

export interface GateResult {
  outcome: GateOutcome;
  reason: string;
  blocking: Finding[];
}

export function evaluateGate(report: NormalizedReport, failOn: FailOn): GateResult {
  // 'none' is not a Severity, and isAtLeast throws on values outside the vocabulary,
  // so this early return is load-bearing: it is what makes an unconditional pass possible.
  if (failOn === 'none') {
    return {
      outcome: 'succeeded',
      reason: `${report.findings.length} finding(s) reported, the gate is disabled (failOn: none)`,
      blocking: [],
    };
  }

  const blocking = report.findings.filter((finding) => isAtLeast(finding.severity, failOn));

  if (blocking.length === 0) {
    if (report.findings.length === 0) {
      return { outcome: 'succeeded', reason: 'No findings', blocking: [] };
    }
    const noun = report.findings.length === 1 ? 'finding' : 'findings';
    return {
      outcome: 'succeededWithIssues',
      reason: `${report.findings.length} ${noun} below the failOn threshold ${failOn}`,
      blocking: [],
    };
  }

  const breakdown = [...SEVERITY_ORDER]
    .reverse()
    .map((severity) => ({
      severity,
      count: blocking.filter((finding) => finding.severity === severity).length,
    }))
    .filter((entry) => entry.count > 0)
    .map((entry) => `${entry.count} ${entry.severity}`)
    .join(', ');

  return {
    outcome: 'failed',
    reason: `${breakdown} at or above the failOn threshold ${failOn}`,
    blocking,
  };
}
