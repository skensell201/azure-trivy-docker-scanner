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

  // A Windows agent path carries a drive letter and backslashes. The logging command
  // syntax only parses up to the closing `]`; everything after it, including the path,
  // is opaque data. Pinning this because the plan text only ever exercises POSIX paths.
  it('passes a Windows-style path through unchanged, after the closing bracket', () => {
    publisher.attachReport('C:\\agent\\_work\\1\\s\\.trivy\\report-0.json', 0);
    expect(lines).toEqual([
      '##vso[task.addattachment type=trivy.report;name=trivy-report-0;]C:\\agent\\_work\\1\\s\\.trivy\\report-0.json',
    ]);
  });

  it('gives two scans in the same job distinct attachment names', () => {
    publisher.attachReport('/agent/_work/1/s/.trivy/report-0.json', 0);
    publisher.attachReport('/agent/_work/1/s/.trivy/report-1.json', 1);
    expect(lines[0]).toContain('name=trivy-report-0;');
    expect(lines[1]).toContain('name=trivy-report-1;');
  });

  it('prints a readable all-zero summary for a clean report, in descending severity order', () => {
    const clean: NormalizedReport = {
      ...report,
      findings: [],
      counts: { UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 },
    };
    publisher.printSummary(clean, 'baseline');
    const severityLines = lines.filter((line) => /^\s*(CRITICAL|HIGH|MEDIUM|LOW|UNKNOWN):/.test(line));
    expect(severityLines).toEqual([
      '  CRITICAL: 0',
      '  HIGH: 0',
      '  MEDIUM: 0',
      '  LOW: 0',
      '  UNKNOWN: 0',
    ]);
  });

  it('prints the trivy binary version when known, alongside the alias and image', () => {
    // Deliberately distinct from the image tag (0.58.1) so this cannot pass by
    // accidentally matching a substring of the "using runner ... (image)" line.
    publisher.printSummary(
      { ...report, runner: { ...report.runner, trivyVersion: '0.59.0' } },
      'baseline',
    );
    expect(lines.join('\n')).toContain('0.59.0');
  });

  it('omits the trivy version line when it is not known', () => {
    publisher.printSummary(report, 'baseline');
    expect(lines.join('\n')).not.toContain('Trivy version');
  });

  describe('logging command injection', () => {
    // Every write() call is one string. If that string contains a raw newline, a real
    // agent parsing stdout line by line would see a second physical line — and if that
    // physical line starts with "##vso[", the agent executes it as its own command.
    // This simulates that split to check what the agent would actually see.
    const physicalLines = () => lines.flatMap((line) => line.split('\n'));

    it('keeps a package name carrying an embedded logging command to a single physical line', () => {
      const malicious = {
        ...report.findings[0],
        pkgName: 'evil-pkg\n##vso[task.complete result=Succeeded]',
      };
      publisher.logBlockingFindings([malicious]);

      const rendered = physicalLines();
      expect(rendered).toHaveLength(1);
      expect(rendered.filter((line) => line.startsWith('##vso['))).toHaveLength(1);
      expect(rendered[0]).not.toContain('##vso[task.complete');
    });

    it('renders a literal ##vso[ occurring in a finding title as inert text', () => {
      const malicious = {
        ...report.findings[0],
        title: 'suspicious ##vso[task.setvariable variable=x;]payload',
      };
      publisher.logBlockingFindings([malicious]);

      expect(lines[0]).not.toContain('##vso[task.setvariable');
      // Still readable: the finding is shown, not deleted.
      expect(lines[0]).toContain('suspicious');
      expect(lines[0]).toContain('payload');
    });

    it('does not let a newline in the attachment path start a second command line', () => {
      publisher.attachReport(
        '/agent/_work/1/s/.trivy/report-0.json\n##vso[task.complete result=Succeeded]',
        0,
      );

      const rendered = physicalLines();
      expect(rendered).toHaveLength(1);
      expect(rendered.filter((line) => line.startsWith('##vso['))).toHaveLength(1);
    });

    it('does not let a newline in a sarif path start a second command line', () => {
      publisher.publishSarif('/agent/_work/1/s/.trivy/report-0.sarif\n##vso[task.complete result=Succeeded]');

      const rendered = physicalLines();
      expect(rendered).toHaveLength(1);
      expect(rendered.filter((line) => line.startsWith('##vso['))).toHaveLength(1);
    });

    it('does not let a newline in an artifact path start a second command line', () => {
      publisher.publishArtifact(
        '/agent/_work/1/s/out.zip\n##vso[task.complete result=Succeeded]',
        'artifact-name',
      );

      const rendered = physicalLines();
      expect(rendered).toHaveLength(1);
      expect(rendered.filter((line) => line.startsWith('##vso['))).toHaveLength(1);
    });
  });
});
