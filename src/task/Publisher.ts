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
   * Registers the JSON report as a build attachment. The results tab reads attachments
   * through the Build REST API, so the attachment name must be unique per scan —
   * several TrivyScan steps can run in one job.
   */
  attachReport(hostPath: string, scanIndex: number): void {
    this.write(
      `##vso[task.addattachment type=trivy.report;name=trivy-report-${scanIndex};]${hostPath}`,
    );
  }

  /** Uploads to the CodeAnalysisLogs artifact, which existing SARIF viewer extensions already know how to render. */
  publishSarif(hostPath: string): void {
    this.write(`##vso[artifact.upload artifactname=CodeAnalysisLogs;]${hostPath}`);
  }

  publishArtifact(hostPath: string, artifactName: string): void {
    this.write(`##vso[artifact.upload artifactname=${artifactName};]${hostPath}`);
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
      const pkg = finding.pkgName
        ? ` in ${finding.pkgName}${finding.installedVersion ? ` ${finding.installedVersion}` : ''}`
        : '';
      const fix = finding.fixedVersion
        ? ` (fixed in ${finding.fixedVersion})`
        : ' (no fix available)';
      this.write(
        `##vso[task.logissue type=error]${finding.severity} ${finding.id}${pkg}${fix}: ${finding.title}`,
      );
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
    if (report.runner.dbUpdatedAt) {
      this.write(`Vulnerability database updated at ${report.runner.dbUpdatedAt}`);
    }
    for (const severity of [...SEVERITY_ORDER].reverse()) {
      this.write(`  ${severity}: ${report.counts[severity]}`);
    }
  }
}
