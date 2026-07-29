import * as fs from 'fs';
import * as path from 'path';
import { parseTrivyReport, parseVersion, TrivyReportParseError } from '../ReportParser';

const fixture = (name: string): string =>
  fs.readFileSync(path.join(__dirname, '../../../test/fixtures/trivy', name), 'utf8');

const meta = { scanType: 'image' as const, target: 'app:1.4.2', runner: { alias: 'baseline', image: 'reg.corp/trivy:0.58.1' } };

describe('parseTrivyReport', () => {
  it('flattens vulnerabilities from every result into findings', () => {
    const report = parseTrivyReport(fixture('image-vulns.json'), meta);
    expect(report.findings).toHaveLength(4);
    expect(report.findings[0]).toEqual({
      kind: 'vulnerability',
      severity: 'CRITICAL',
      id: 'CVE-2024-21626',
      title: 'runc: file descriptor leak allows container escape',
      target: 'app:1.4.2 (debian 12.5)',
      pkgName: 'runc',
      installedVersion: '1.1.7-0+deb12u1',
      fixedVersion: '1.1.12-0+deb12u1',
    });
  });

  it('counts findings per severity', () => {
    const report = parseTrivyReport(fixture('image-vulns.json'), meta);
    expect(report.counts).toEqual({ UNKNOWN: 0, LOW: 0, MEDIUM: 1, HIGH: 1, CRITICAL: 2 });
  });

  it('counts findings per kind', () => {
    const report = parseTrivyReport(fixture('image-vulns.json'), meta);
    expect(report.kindCounts).toEqual({
      vulnerability: 4,
      secret: 0,
      misconfiguration: 0,
      license: 0,
    });
  });

  it('carries artifact name and creation time from the report', () => {
    const report = parseTrivyReport(fixture('image-vulns.json'), meta);
    expect(report.artifactName).toBe('app:1.4.2');
    expect(report.createdAt).toBe('2026-07-28T09:12:44.512Z');
  });

  it('returns an empty report with zeroed counts when nothing was found', () => {
    const report = parseTrivyReport(fixture('empty.json'), meta);
    expect(report.findings).toEqual([]);
    expect(report.counts.CRITICAL).toBe(0);
  });

  it('reads secrets and keeps their file location', () => {
    const report = parseTrivyReport(fixture('secrets-and-misconfig.json'), meta);
    const secret = report.findings.find((finding) => finding.kind === 'secret');
    expect(secret).toEqual({
      kind: 'secret',
      severity: 'CRITICAL',
      id: 'aws-access-key-id',
      title: 'AWS Access Key ID',
      target: 'deploy/values.yaml',
      location: 'deploy/values.yaml:14',
    });
  });

  it('reads only failing misconfigurations', () => {
    const report = parseTrivyReport(fixture('secrets-and-misconfig.json'), meta);
    const misconfigurations = report.findings.filter(
      (finding) => finding.kind === 'misconfiguration',
    );
    expect(misconfigurations).toEqual([
      {
        kind: 'misconfiguration',
        severity: 'HIGH',
        id: 'DS002',
        title: "Image user should not be 'root'",
        target: 'Dockerfile',
      },
    ]);
  });

  it('rejects malformed json with the runner and target in the message', () => {
    expect(() => parseTrivyReport('{not json', meta)).toThrow(TrivyReportParseError);
    expect(() => parseTrivyReport('{not json', meta)).toThrow(/reg.corp\/trivy:0.58.1/);
  });

  it('rejects a json document that is not a trivy report', () => {
    expect(() => parseTrivyReport('{"hello":"world"}', meta)).toThrow(/Results/);
  });
});

describe('parseVersion', () => {
  it('extracts the trivy version and the database timestamp', () => {
    expect(parseVersion(fixture('version.json'))).toEqual({
      trivyVersion: '0.58.1',
      dbUpdatedAt: '2026-07-28T06:11:53.123456789Z',
    });
  });

  it('returns an empty object when the output cannot be parsed', () => {
    expect(parseVersion('not json')).toEqual({});
  });
});
