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

describe('parseTrivyReport self-review pins', () => {
  // Pins a real asymmetry in the implementation: FixedVersion is omitted from the finding
  // when trivy did not report one, while PkgName/InstalledVersion are always assigned even
  // when undefined (a present key with an undefined value). JSON.stringify would serialize
  // both the same way, but `'fixedVersion' in finding` would not — so this locks in which
  // behavior is intended.
  it('omits fixedVersion entirely for a vulnerability trivy reported no fix for', () => {
    const report = parseTrivyReport(fixture('image-vulns.json'), meta);
    const zlib = report.findings.find((finding) => finding.id === 'CVE-2023-45853');
    expect(zlib).toBeDefined();
    expect('fixedVersion' in (zlib as object)).toBe(false);
  });

  // A result with no Target attributes its findings to the overall scan target rather than
  // to "undefined" or an empty string.
  it('falls back to the scan target when a result has no Target of its own', () => {
    const raw = JSON.stringify({
      SchemaVersion: 2,
      Results: [
        {
          Vulnerabilities: [
            { VulnerabilityID: 'CVE-0000-0000', Severity: 'HIGH', Title: 'missing target case' },
          ],
        },
      ],
    });
    const report = parseTrivyReport(raw, meta);
    expect(report.findings[0].target).toBe(meta.target);
  });

  // None of the four plan fixtures include a Licenses array, so license handling is
  // otherwise untested. Pins that the title is readable (category plus license name) and
  // that pkgName travels along so the finding can actually be acted on.
  it('reads a license finding with a readable title and its package name', () => {
    const raw = JSON.stringify({
      SchemaVersion: 2,
      Results: [
        {
          Target: 'app/go.sum',
          Licenses: [
            { Name: 'GPL-3.0', PkgName: 'some-copyleft-lib', Severity: 'HIGH', Category: 'restricted' },
          ],
        },
      ],
    });
    const report = parseTrivyReport(raw, meta);
    expect(report.findings[0]).toEqual({
      kind: 'license',
      severity: 'HIGH',
      id: 'GPL-3.0',
      title: 'restricted: GPL-3.0',
      target: 'app/go.sum',
      pkgName: 'some-copyleft-lib',
    });
  });

  // counts and kindCounts are both derived by iterating the same findings array once, each
  // finding incrementing exactly one severity bucket and one kind bucket, so they cannot
  // disagree with findings.length by construction. Pins that invariant across every fixture.
  it.each(['image-vulns.json', 'empty.json', 'secrets-and-misconfig.json'])(
    'keeps counts and kindCounts summing to findings.length for %s',
    (name) => {
      const report = parseTrivyReport(fixture(name), meta);
      const countsSum = Object.values(report.counts).reduce((sum, n) => sum + n, 0);
      const kindCountsSum = Object.values(report.kindCounts).reduce((sum, n) => sum + n, 0);
      expect(countsSum).toBe(report.findings.length);
      expect(kindCountsSum).toBe(report.findings.length);
    },
  );
});

describe('control character normalization', () => {
  // Findings carry text straight out of scanned lockfiles (filesystem/repository scans),
  // which is controlled by whoever publishes a dependency. The Publisher writes findings
  // into Azure Pipelines logging commands parsed line by line from stdout, where a newline
  // starts a new line and a line starting with `##vso[` is executed as a command. A package
  // named with an embedded newline followed by `##vso[task.complete result=Succeeded]` must
  // not survive into the data model as a literal newline, or it can mark a failed scan as
  // passed regardless of how carefully the Publisher escapes elsewhere.
  it('strips an injected pipeline logging command out of a package name', () => {
    const raw = JSON.stringify({
      SchemaVersion: 2,
      Results: [
        {
          Target: 'app:1.4.2',
          Vulnerabilities: [
            {
              VulnerabilityID: 'CVE-2024-0001',
              PkgName: 'evil-pkg\n##vso[task.complete result=Succeeded]',
              InstalledVersion: '1.0.0',
              Severity: 'HIGH',
              Title: 'injection attempt',
            },
          ],
        },
      ],
    });
    const report = parseTrivyReport(raw, meta);
    const pkgName = report.findings[0].pkgName;
    expect(pkgName).not.toContain('\n');
    expect(pkgName).not.toContain('\r');
    expect(pkgName).toBe('evil-pkg ##vso[task.complete result=Succeeded]');
  });

  it('collapses a CRLF-laden title to single spaces', () => {
    const raw = JSON.stringify({
      SchemaVersion: 2,
      Results: [
        {
          Target: 'app:1.4.2',
          Vulnerabilities: [
            {
              VulnerabilityID: 'CVE-2024-0002',
              Severity: 'HIGH',
              Title: 'line one\r\nline two\tline three',
            },
          ],
        },
      ],
    });
    const report = parseTrivyReport(raw, meta);
    expect(report.findings[0].title).toBe('line one line two line three');
  });

  it('leaves an ordinary title with normal punctuation unchanged', () => {
    const report = parseTrivyReport(fixture('image-vulns.json'), meta);
    expect(report.findings[0].title).toBe('runc: file descriptor leak allows container escape');
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
