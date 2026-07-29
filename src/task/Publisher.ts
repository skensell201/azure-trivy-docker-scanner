import { compareSeverity, SEVERITY_ORDER } from '../shared/severity';
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
   * Any stdout line beginning with `##vso[` is executed by the agent as a command,
   * regardless of which code emitted it or which field the text came from. That means
   * every value interpolated anywhere in this class — finding titles, package names,
   * versions, file paths, the scan target, the runner alias, image and versions — must
   * be routed through here before it reaches a `write()` call. It is tempting to treat
   * some fields as "safe" because they look administrator-controlled, but `target` is
   * proof that intuition fails: it is the one input deliberately left outside the
   * override policy (it *is* the scan), so a pipeline author who cannot bypass the gate
   * through `severities` or `failOn` could otherwise bypass it entirely here. Do not add
   * a sixth interpolated field without sanitizing it.
   *
   * Two defences, both needed:
   *  - a raw newline would start a second physical line, so newlines become a space;
   *  - a literal "##vso[" would make that second line a command of the attacker's
   *    choosing (e.g. `task.complete result=Succeeded`, marking a failed build as
   *    successful), so the "##" prefix is broken while leaving the rest of the text
   *    readable.
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
    // `target` is a pipeline input, not an admin-controlled one — see the note on
    // sanitizeForLogLine. It goes through the same helper as every other value here.
    const target = this.sanitizeForLogLine(report.target);
    const runner = this.sanitizeForLogLine(runnerAlias);
    const image = this.sanitizeForLogLine(report.runner.image);

    this.write(`Trivy scan of ${target} using runner ${runner} (${image})`);
    if (report.runner.trivyVersion) {
      this.write(`Trivy version: ${this.sanitizeForLogLine(report.runner.trivyVersion)}`);
    }
    if (report.runner.dbUpdatedAt) {
      this.write(
        `Vulnerability database updated at ${this.sanitizeForLogLine(report.runner.dbUpdatedAt)}`,
      );
    }
    for (const severity of [...SEVERITY_ORDER].reverse()) {
      this.write(`  ${severity}: ${report.counts[severity]}`);
    }
  }

  /** A build issue at warning level: used for problems that must be visible but must
   * never fail the build by themselves (e.g. an extra output format that could not be
   * produced). The message goes through sanitizeForLogLine like every other value this
   * class writes - see the class doc comment. */
  warn(message: string): void {
    this.write(`##vso[task.logissue type=warning]${this.sanitizeForLogLine(message)}`);
  }

  /**
   * Renders the findings already parsed into the report as a plain log table, most to
   * least severe. This is not a second trivy invocation - scanning twice to get text
   * instead of JSON would double the build time for nothing - so it works from the
   * same NormalizedReport the gate already evaluated.
   *
   * Column widths are for alignment only, never for truncation: padEnd never slice()s,
   * so a long package name (npm scoped names and Java group/artifact ids routinely run
   * past 25 characters) stays fully readable even if that one row does not line up
   * under the header.
   */
  printFindingsTable(report: NormalizedReport): void {
    if (report.findings.length === 0) {
      this.write('No findings.');
      return;
    }

    const rows = [...report.findings].sort((a, b) => compareSeverity(b.severity, a.severity));

    this.write('SEVERITY  ID                    PACKAGE                        FIXED IN');
    for (const finding of rows) {
      // Every one of these can originate from a scanned artifact (e.g. a lockfile
      // package name), so each goes through sanitizeForLogLine before reaching write()
      // - same rule as logBlockingFindings and printSummary.
      const id = this.sanitizeForLogLine(finding.id);
      const pkgName = finding.pkgName ? this.sanitizeForLogLine(finding.pkgName) : undefined;
      const installedVersion = finding.installedVersion
        ? this.sanitizeForLogLine(finding.installedVersion)
        : undefined;
      const fixedVersion = finding.fixedVersion
        ? this.sanitizeForLogLine(finding.fixedVersion)
        : undefined;
      const target = this.sanitizeForLogLine(finding.target);

      const pkg = `${pkgName ?? target}${installedVersion ? ` ${installedVersion}` : ''}`;

      this.write(
        `${finding.severity.padEnd(9)} ${id.padEnd(21)} ${pkg.padEnd(30)} ${fixedVersion ?? '-'}`,
      );
    }
  }
}
