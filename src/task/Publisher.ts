import { SEVERITY_ORDER } from '../shared/severity';
import { Finding, NormalizedReport } from '../shared/types';

/**
 * Azure Pipelines has no API for this: an agent task talks to the server by printing
 * specially formatted "logging command" lines to stdout. The line writer is injected
 * so this module is testable by capturing strings, with no agent involved.
 */
export type LineWriter = (line: string) => void;

const MAX_LOGGED_FINDINGS = 20;

function pluralize(count: number, noun: string): string {
  return `${count} ${count === 1 ? noun : `${noun}s`}`;
}

export class Publisher {
  constructor(private readonly write: LineWriter = (line) => console.log(line)) {}

  /**
   * The agent parses stdout line by line, and a line starting with `##vso[` is a
   * command it executes. Every caller-supplied value that lands inside a logging
   * command line — finding titles, package names, versions, file paths — must be
   * routed through here first. Two defences, both needed:
   *  - a raw newline would start a second physical line, so newlines become a space;
   *  - a literal "##vso[" would make that second line a command of the attacker's
   *    choosing (e.g. `task.complete result=Succeeded`, masking a failed scan), so the
   *    "##" prefix is broken while leaving the rest of the text readable.
   * This is defence in depth: ReportParser also normalises these fields at the point
   * they enter the data model, but that does not make this boundary check redundant —
   * a future caller of Publisher need not go through ReportParser at all.
   */
  private sanitizeForLogLine(text: string): string {
    const singleLine = text.replace(/\r\n|\r|\n/g, ' ');
    const inert = singleLine.replace(/##vso\[/gi, '#-vso[');
    return inert.replace(/\s+/g, ' ').trim();
  }

  /**
   * Registers the JSON report as a build attachment. The results tab reads attachments
   * through the Build REST API, so the attachment name must be unique per scan —
   * several TrivyScan steps can run in one job.
   */
  attachReport(hostPath: string, scanIndex: number): void {
    this.write(
      `##vso[task.addattachment type=trivy.report;name=trivy-report-${scanIndex};]${this.sanitizeForLogLine(hostPath)}`,
    );
  }

  /** Uploads to the CodeAnalysisLogs artifact, which existing SARIF viewer extensions already know how to render. */
  publishSarif(hostPath: string): void {
    this.write(`##vso[artifact.upload artifactname=CodeAnalysisLogs;]${this.sanitizeForLogLine(hostPath)}`);
  }

  publishArtifact(hostPath: string, artifactName: string): void {
    this.write(
      `##vso[artifact.upload artifactname=${artifactName};]${this.sanitizeForLogLine(hostPath)}`,
    );
  }

  /**
   * Emits one build issue per blocking finding, which is what makes findings appear in
   * the build summary rather than only in the log. Capped because a report with
   * hundreds of findings would otherwise bury the summary. The cap is safe because
   * callers pass `GateResult.blocking`, which `GateEvaluator` sorts from most to least
   * severe: the findings that survive the cap are the most severe ones.
   */
  logBlockingFindings(findings: Finding[]): void {
    for (const finding of findings.slice(0, MAX_LOGGED_FINDINGS)) {
      // pkgName, installedVersion, fixedVersion and title are read out of scanned
      // artifacts (e.g. lockfile package names), not from a fixed vocabulary like
      // severity or id's usual CVE shape — an attacker who controls a scanned
      // dependency controls these strings, so every one goes through sanitizeForLogLine.
      const id = this.sanitizeForLogLine(finding.id);
      const pkgName = finding.pkgName ? this.sanitizeForLogLine(finding.pkgName) : undefined;
      const installedVersion = finding.installedVersion
        ? this.sanitizeForLogLine(finding.installedVersion)
        : undefined;
      const fixedVersion = finding.fixedVersion
        ? this.sanitizeForLogLine(finding.fixedVersion)
        : undefined;
      const title = this.sanitizeForLogLine(finding.title);

      const pkg = pkgName ? ` in ${pkgName}${installedVersion ? ` ${installedVersion}` : ''}` : '';
      const fix = fixedVersion ? ` (fixed in ${fixedVersion})` : ' (no fix available)';
      this.write(`##vso[task.logissue type=error]${finding.severity} ${id}${pkg}${fix}: ${title}`);
    }

    const hidden = findings.length - MAX_LOGGED_FINDINGS;
    if (hidden > 0) {
      this.write(
        `##vso[task.logissue type=error]${pluralize(hidden, 'more blocking finding')} not listed here, see the Trivy tab.`,
      );
    }
  }

  printSummary(report: NormalizedReport, runnerAlias: string): void {
    this.write(
      `Trivy scan of ${report.target} using runner ${runnerAlias} (${report.runner.image})`,
    );
    if (report.runner.trivyVersion) {
      this.write(`Trivy version: ${report.runner.trivyVersion}`);
    }
    if (report.runner.dbUpdatedAt) {
      this.write(`Vulnerability database updated at ${report.runner.dbUpdatedAt}`);
    }
    for (const severity of [...SEVERITY_ORDER].reverse()) {
      this.write(`  ${severity}: ${report.counts[severity]}`);
    }
  }
}
