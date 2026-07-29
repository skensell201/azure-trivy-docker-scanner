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
    runner: { alias: 'baseline', image: 'reg.corp/trivy:0.58.1' },
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

  it('explains a failure with the counts that crossed the threshold', () => {
    const result = evaluateGate(
      report([finding('CRITICAL', 'CVE-1'), finding('CRITICAL', 'CVE-2'), finding('HIGH', 'CVE-3')]),
      'HIGH',
    );
    expect(result.reason).toBe('2 CRITICAL, 1 HIGH at or above the failOn threshold HIGH');
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
    expect(result.reason).toBe('1 CRITICAL at or above the failOn threshold CRITICAL');
  });

  it('gives an exact reason when there are no findings at all', () => {
    const result = evaluateGate(report([]), 'CRITICAL');
    expect(result.reason).toBe('No findings');
  });

  it('reports the exact count when the gate is disabled with findings present', () => {
    const result = evaluateGate(report([finding('CRITICAL', 'CVE-1')]), 'none');
    expect(result.reason).toBe('1 finding(s) reported, the gate is disabled (failOn: none)');
  });

  it('omits a severity from the breakdown when it has zero findings, even inside the blocking band', () => {
    const result = evaluateGate(
      report([finding('CRITICAL', 'CVE-1'), finding('CRITICAL', 'CVE-2'), finding('MEDIUM', 'CVE-3')]),
      'MEDIUM',
    );
    expect(result.reason).toBe('2 CRITICAL, 1 MEDIUM at or above the failOn threshold MEDIUM');
  });
});
