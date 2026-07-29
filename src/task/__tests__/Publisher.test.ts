import { Publisher } from '../Publisher';
import { NormalizedReport } from '../../shared/types';

const report: NormalizedReport = {
  schemaVersion: 1,
  scanType: 'image',
  target: 'app:1.4.2',
  artifactName: 'app:1.4.2',
  runner: { alias: 'baseline', image: 'reg.corp/trivy:0.58.1' },
  findings: [
    {
      kind: 'vulnerability',
      severity: 'CRITICAL',
      id: 'CVE-2024-21626',
      title: 'runc escape',
      target: 'app:1.4.2',
      pkgName: 'runc',
      installedVersion: '1.1.7',
      fixedVersion: '1.1.12',
    },
  ],
  counts: { UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 1 },
  kindCounts: { vulnerability: 1, secret: 0, misconfiguration: 0, license: 0 },
};

describe('Publisher', () => {
  let lines: string[];
  let publisher: Publisher;

  beforeEach(() => {
    lines = [];
    publisher = new Publisher((line) => lines.push(line));
  });

  it('attaches the report under the trivy.report type with a per-scan name', () => {
    publisher.attachReport('/agent/_work/1/s/.trivy/report-2.json', 2);
    expect(lines).toEqual([
      '##vso[task.addattachment type=trivy.report;name=trivy-report-2;]/agent/_work/1/s/.trivy/report-2.json',
    ]);
  });

  it('uploads the sarif file into the CodeAnalysisLogs artifact', () => {
    publisher.publishSarif('/agent/_work/1/s/.trivy/report-0.sarif');
    expect(lines).toEqual([
      '##vso[artifact.upload artifactname=CodeAnalysisLogs;]/agent/_work/1/s/.trivy/report-0.sarif',
    ]);
  });

  it('logs one error per blocking finding so they surface in the build summary', () => {
    publisher.logBlockingFindings(report.findings);
    expect(lines).toEqual([
      '##vso[task.logissue type=error]CRITICAL CVE-2024-21626 in runc 1.1.7 (fixed in 1.1.12): runc escape',
    ]);
  });

  it('says when a finding has no fix available', () => {
    publisher.logBlockingFindings([{ ...report.findings[0], fixedVersion: undefined }]);
    expect(lines[0]).toContain('(no fix available)');
  });

  it('caps the number of logged findings and says how many were hidden', () => {
    const many = Array.from({ length: 30 }, (_, index) => ({
      ...report.findings[0],
      id: `CVE-${index}`,
    }));
    publisher.logBlockingFindings(many);
    expect(lines).toHaveLength(21);
    expect(lines[20]).toContain('10 more blocking findings not listed here');
  });

  it('prints a summary table of severity counts', () => {
    publisher.printSummary(report, 'baseline');
    expect(lines.join('\n')).toContain('CRITICAL: 1');
    expect(lines.join('\n')).toContain('baseline');
  });
});
