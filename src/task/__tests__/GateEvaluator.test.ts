import { evaluateGate } from '../GateEvaluator';
import { Finding, NormalizedReport, Severity } from '../../shared/types';

const finding = (severity: Severity, id: string): Finding => ({
  kind: 'vulnerability',
  severity,
  id,
  title: `${id} title`,
  target: 'app:1.4.2',
});

const findingOfKind = (kind: Finding['kind'], severity: Severity, id: string): Finding => ({
  kind,
  severity,
  id,
  title: `${id} title`,
  target: 'app:1.4.2',
});

const report = (findings: Finding[]): NormalizedReport => {
  const counts = { UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 };
  findings.forEach((item) => (counts[item.severity] += 1));
  return {
    schemaVersion: 1,
    scanType: 'image',
    target: 'app:1.4.2',
    artifactName: 'app:1.4.2',
    runner: { alias: 'baseline', image: 'registry.example.com/trivy:0.58.1' },
    findings,
    counts,
    kindCounts: { vulnerability: findings.length, secret: 0, misconfiguration: 0, license: 0 },
  };
};

describe('evaluateGate', () => {
  it('succeeds on a clean report', () => {
    const result = evaluateGate(report([]), 'CRITICAL');
    expect(result.outcome).toBe('succeeded');
    expect(result.blocking).toEqual([]);
  });

  it('fails when a finding reaches the threshold', () => {
    const result = evaluateGate(report([finding('CRITICAL', 'CVE-1')]), 'CRITICAL');
    expect(result.outcome).toBe('failed');
    expect(result.blocking).toHaveLength(1);
  });

  it('counts every finding at or above the threshold as blocking', () => {
    const result = evaluateGate(
      report([finding('CRITICAL', 'CVE-1'), finding('HIGH', 'CVE-2'), finding('LOW', 'CVE-3')]),
      'HIGH',
    );
    expect(result.blocking.map((item) => item.id)).toEqual(['CVE-1', 'CVE-2']);
  });

  it('warns instead of failing when findings stay below the threshold', () => {
    const result = evaluateGate(report([finding('MEDIUM', 'CVE-1')]), 'CRITICAL');
    expect(result.outcome).toBe('succeededWithIssues');
  });

  it('succeeds regardless of findings when the gate is disabled', () => {
    const result = evaluateGate(report([finding('CRITICAL', 'CVE-1')]), 'none');
    expect(result.outcome).toBe('succeeded');
    expect(result.reason).toMatch(/gate is disabled/i);
  });

  it('explains a failure with the counts that crossed the threshold and the total findings in the report', () => {
    const result = evaluateGate(
      report([
        finding('CRITICAL', 'CVE-1'),
        finding('CRITICAL', 'CVE-2'),
        finding('HIGH', 'CVE-3'),
        finding('LOW', 'CVE-4'),
      ]),
      'HIGH',
    );
    expect(result.reason).toBe(
      '2 CRITICAL, 1 HIGH at or above the failOn threshold HIGH (4 findings total)',
    );
  });

  it('explains a warning with the total number of findings', () => {
    const result = evaluateGate(report([finding('LOW', 'CVE-1')]), 'CRITICAL');
    expect(result.reason).toBe('1 finding below the failOn threshold CRITICAL');
  });

  // Self-review: NormalizedReport.findings mixes all four kinds behind one `severity`
  // field, and the filter below reads only that field, so a secret or a misconfiguration
  // blocks the gate exactly as a vulnerability of the same severity would.
  it('gates secrets and misconfigurations by severity exactly like vulnerabilities', () => {
    const result = evaluateGate(
      report([
        findingOfKind('secret', 'CRITICAL', 'SECRET-1'),
        findingOfKind('misconfiguration', 'HIGH', 'MISCONFIG-1'),
        findingOfKind('vulnerability', 'LOW', 'CVE-1'),
      ]),
      'HIGH',
    );
    expect(result.outcome).toBe('failed');
    expect(result.blocking.map((item) => item.id)).toEqual(['SECRET-1', 'MISCONFIG-1']);
  });

  it('produces a singular-safe reason for exactly one blocking finding', () => {
    const result = evaluateGate(report([finding('CRITICAL', 'CVE-1')]), 'CRITICAL');
    expect(result.reason).toBe('1 CRITICAL at or above the failOn threshold CRITICAL (1 finding total)');
  });

  it('gives an exact reason when there are no findings at all', () => {
    const result = evaluateGate(report([]), 'CRITICAL');
    expect(result.reason).toBe('No findings');
  });

  it('reports a properly pluralized count when the gate is disabled with one finding present', () => {
    const result = evaluateGate(report([finding('CRITICAL', 'CVE-1')]), 'none');
    expect(result.reason).toBe('1 finding reported, the gate is disabled (failOn: none)');
  });

  it('omits a severity from the breakdown when it has zero findings, even inside the blocking band', () => {
    const result = evaluateGate(
      report([finding('CRITICAL', 'CVE-1'), finding('CRITICAL', 'CVE-2'), finding('MEDIUM', 'CVE-3')]),
      'MEDIUM',
    );
    expect(result.reason).toBe(
      '2 CRITICAL, 1 MEDIUM at or above the failOn threshold MEDIUM (3 findings total)',
    );
  });

  // Fix 1: the publisher and the results tab both truncate `findings.slice(0, 20)`.
  // Report order is whatever trivy happened to emit; without sorting here, a report
  // with 40 MEDIUM findings before 3 CRITICAL ones would show only MEDIUM findings
  // and drop every CRITICAL into "20 more".
  it('returns blocking findings sorted from most to least severe regardless of report order', () => {
    const result = evaluateGate(
      report([finding('LOW', 'CVE-1'), finding('CRITICAL', 'CVE-2'), finding('MEDIUM', 'CVE-3')]),
      'LOW',
    );
    expect(result.blocking.map((item) => item.id)).toEqual(['CVE-2', 'CVE-3', 'CVE-1']);
  });

  // Fix 4.1: the entry point only calls publisher.logBlockingFindings when
  // gate.blocking.length > 0. A disabled gate must report zero blocking findings,
  // not the full findings list, or it would log every finding as a build issue.
  it('returns no blocking findings when the gate is disabled, even though findings exist', () => {
    const result = evaluateGate(
      report([finding('CRITICAL', 'CVE-1'), finding('CRITICAL', 'CVE-2')]),
      'none',
    );
    expect(result.blocking).toEqual([]);
  });

  it('pluralizes the warning reason when more than one finding stays below the threshold', () => {
    const result = evaluateGate(
      report([finding('MEDIUM', 'CVE-1'), finding('LOW', 'CVE-2')]),
      'CRITICAL',
    );
    expect(result.reason).toBe('2 findings below the failOn threshold CRITICAL');
  });

  // Fix 4.3: nothing in the earlier suite ever constructed an UNKNOWN finding, so the
  // filter excluding it from every reachable threshold (UNKNOWN is no longer a valid
  // FailOn) went unpinned.
  it('does not let an UNKNOWN-severity finding block a threshold, even the lowest one', () => {
    const result = evaluateGate(
      report([finding('UNKNOWN', 'CVE-1'), finding('LOW', 'CVE-2')]),
      'LOW',
    );
    expect(result.blocking.map((item) => item.id)).toEqual(['CVE-2']);
  });

  it('pluralizes the disabled-gate reason for more than one finding', () => {
    const result = evaluateGate(
      report([finding('CRITICAL', 'CVE-1'), finding('HIGH', 'CVE-2')]),
      'none',
    );
    expect(result.reason).toBe('2 findings reported, the gate is disabled (failOn: none)');
  });

  it('gives a sensible disabled-gate reason for a clean report', () => {
    const result = evaluateGate(report([]), 'none');
    expect(result.reason).toBe('No findings, the gate is disabled (failOn: none)');
  });

  it('reports the applied threshold on every outcome', () => {
    expect(evaluateGate(report([]), 'CRITICAL').threshold).toBe('CRITICAL');
    expect(evaluateGate(report([finding('CRITICAL', 'CVE-1')]), 'none').threshold).toBe('none');
  });

  it('gives per-severity and per-kind counts of only the blocking findings, not the whole report', () => {
    const result = evaluateGate(
      report([
        findingOfKind('secret', 'CRITICAL', 'SECRET-1'),
        findingOfKind('vulnerability', 'CRITICAL', 'CVE-1'),
        findingOfKind('vulnerability', 'HIGH', 'CVE-2'),
        findingOfKind('vulnerability', 'LOW', 'CVE-3'),
      ]),
      'HIGH',
    );
    expect(result.blockingCounts).toEqual({ UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 1, CRITICAL: 2 });
    expect(result.blockingKindCounts).toEqual({
      vulnerability: 2,
      secret: 1,
      misconfiguration: 0,
      license: 0,
    });
  });

  it('returns zeroed blocking counts when nothing blocks, even though the report has findings', () => {
    const result = evaluateGate(report([finding('LOW', 'CVE-1')]), 'CRITICAL');
    expect(result.blockingCounts).toEqual({ UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 });
    expect(result.blockingKindCounts).toEqual({
      vulnerability: 0,
      secret: 0,
      misconfiguration: 0,
      license: 0,
    });
  });
});
