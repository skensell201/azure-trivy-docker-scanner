import { Publisher } from '../Publisher';
import { NormalizedReport } from '../../shared/types';

const report: NormalizedReport = {
  schemaVersion: 1,
  scanType: 'image',
  target: 'app:1.4.2',
  artifactName: 'app:1.4.2',
  runner: { alias: 'baseline', image: 'registry.example.com/trivy:0.58.1' },
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

  it('points the over-cap message at the attached report and the published artifact, not a build results tab that does not exist yet', () => {
    const many = Array.from({ length: 21 }, (_, index) => ({
      ...report.findings[0],
      id: `CVE-${index}`,
    }));
    publisher.logBlockingFindings(many);
    expect(lines[20]).toContain('see the attached report or the published artifact');
    expect(lines[20]).not.toContain('Trivy tab');
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

  it('publishes JUnit test results with mergeResults=false and the given run title', () => {
    publisher.publishJUnit('/agent/_work/1/s/.trivy/junit-0.xml', 'Trivy - app:1.4.2');
    expect(lines).toEqual([
      '##vso[results.publish type=JUnit;mergeResults=false;runTitle=Trivy - app:1.4.2;]/agent/_work/1/s/.trivy/junit-0.xml',
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

    it('does not let a newline in the JUnit file path start a second command line', () => {
      publisher.publishJUnit(
        '/agent/_work/1/s/.trivy/junit-0.xml\n##vso[task.complete result=Succeeded]',
        'Trivy',
      );

      const rendered = physicalLines();
      expect(rendered).toHaveLength(1);
      expect(rendered.filter((line) => line.startsWith('##vso['))).toHaveLength(1);
    });

    // `runTitle` traces back to report.artifactName, which traces back to the scan `target` -
    // the one field deliberately left outside the override policy (see the class doc comment) -
    // so an embedded logging command in it must not produce a second, attacker-chosen line.
    it('does not let an embedded logging command in the JUnit run title produce a second command line', () => {
      publisher.publishJUnit(
        '/agent/_work/1/s/.trivy/junit-0.xml',
        'Trivy\n##vso[task.complete result=Succeeded]',
      );

      const rendered = physicalLines();
      expect(rendered).toHaveLength(1);
      expect(rendered.filter((line) => line.startsWith('##vso['))).toHaveLength(1);
      expect(rendered[0]).not.toContain('##vso[task.complete');
    });

    // `target` is the one input deliberately left outside the override policy, because
    // it *is* the scan. A pipeline author who cannot bypass the gate through severities
    // or failOn could otherwise bypass it entirely here: printSummary would echo target
    // verbatim, and an embedded "\n##vso[task.complete result=Succeeded]" would be read
    // by the agent as a command marking the build successful.
    it('does not let an embedded logging command in the scan target produce a line the agent would execute', () => {
      const malicious: NormalizedReport = {
        ...report,
        target: 'app:1.4.2\n##vso[task.complete result=Succeeded]',
      };
      publisher.printSummary(malicious, 'baseline');

      const rendered = physicalLines();
      expect(rendered.filter((line) => line.startsWith('##vso['))).toHaveLength(0);
    });

    it('keeps a package name carrying an embedded logging command to a single physical line in the findings table', () => {
      const malicious = {
        ...report.findings[0],
        pkgName: 'evil-pkg\n##vso[task.complete result=Succeeded]',
      };
      publisher.printFindingsTable({ ...report, findings: [malicious] });

      const rendered = physicalLines();
      expect(rendered.filter((line) => line.startsWith('##vso['))).toHaveLength(0);
    });

    it('does not let an embedded logging command in a warning message produce a second command line', () => {
      publisher.warn('trouble\n##vso[task.complete result=Succeeded]');

      const rendered = physicalLines();
      expect(rendered.filter((line) => line.startsWith('##vso['))).toHaveLength(1);
      expect(rendered[0]).not.toContain('##vso[task.complete');
    });
  });

  describe('printFindingsTable', () => {
    it('renders a table of findings sorted by severity', () => {
      publisher.printFindingsTable(report);
      const text = lines.join('\n');
      expect(text).toContain('CRITICAL');
      expect(text).toContain('CVE-2024-21626');
      expect(text).toContain('runc');
    });

    it('says so instead of printing an empty table', () => {
      publisher.printFindingsTable({ ...report, findings: [] });
      expect(lines.join('\n')).toMatch(/no findings/i);
    });

    it('sorts findings from most to least severe', () => {
      const mixed: NormalizedReport = {
        ...report,
        findings: [
          { ...report.findings[0], severity: 'LOW', id: 'CVE-LOW' },
          { ...report.findings[0], severity: 'CRITICAL', id: 'CVE-CRIT' },
          { ...report.findings[0], severity: 'MEDIUM', id: 'CVE-MED' },
        ],
      };
      publisher.printFindingsTable(mixed);
      const text = lines.join('\n');
      expect(text.indexOf('CVE-CRIT')).toBeLessThan(text.indexOf('CVE-MED'));
      expect(text.indexOf('CVE-MED')).toBeLessThan(text.indexOf('CVE-LOW'));
    });

    // A design choice worth pinning: the column widths are for alignment only, never
    // for truncation. A long package name (npm scoped names and Java group/artifact
    // ids routinely run past 25 characters) must remain fully readable even if that
    // row no longer lines up under the header.
    it('does not truncate a long package name', () => {
      const longName = 'org.apache.some.very.long.groupid.and.artifact-name-that-keeps-going';
      publisher.printFindingsTable({
        ...report,
        findings: [{ ...report.findings[0], pkgName: longName }],
      });
      expect(lines.join('\n')).toContain(longName);
    });
  });

  describe('warn', () => {
    it('emits a warning issue', () => {
      publisher.warn('sarif run failed');
      expect(lines).toEqual(['##vso[task.logissue type=warning]sarif run failed']);
    });
  });

  describe('sanitizeForLogLine robustness against unexpected types', () => {
    // parseVersion reads `Version` straight out of `trivy version --format json`. A
    // misbehaving runner image can hand back {"Version": 42} instead of a string, and
    // that number reaches sanitizeForLogLine through trivyVersion despite RunnerInfo
    // declaring it a string. ReportParser is being fixed to coerce its own output, but
    // this is the boundary every other module trusts, and a boundary that crashes on an
    // unexpected type after a successful scan is not much of a boundary.
    it('stringifies a numeric trivy version instead of throwing', () => {
      const malformed = {
        ...report,
        runner: { ...report.runner, trivyVersion: 42 as unknown as string },
      };
      expect(() => publisher.printSummary(malformed, 'baseline')).not.toThrow();
      expect(lines.join('\n')).toContain('42');
    });

    it('treats null as an empty string instead of printing the word "null"', () => {
      const malformed = { ...report, target: null as unknown as string };
      expect(() => publisher.printSummary(malformed, 'baseline')).not.toThrow();
      expect(lines.join('\n')).not.toContain('null');
    });

    it('treats undefined as an empty string instead of printing the word "undefined"', () => {
      const malformed = { ...report, target: undefined as unknown as string };
      expect(() => publisher.printSummary(malformed, 'baseline')).not.toThrow();
      expect(lines.join('\n')).not.toContain('undefined');
    });

    it('stringifies an object instead of throwing, and still emits a single safe line', () => {
      const malformed = { ...report, target: { unexpected: true } as unknown as string };
      expect(() => publisher.printSummary(malformed, 'baseline')).not.toThrow();
      const rendered = lines.flatMap((line) => line.split('\n'));
      expect(rendered.filter((line) => line.startsWith('##vso['))).toHaveLength(0);
    });
  });
});
