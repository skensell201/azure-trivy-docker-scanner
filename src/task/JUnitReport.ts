import { Finding, NormalizedReport } from '../shared/types';

export interface JUnitReportOptions {
  /** Human-readable label for the `<testsuite name="...">` attribute and, by convention in
   * run.ts, the `results.publish` run title too. Sanitized and escaped the same as every
   * other value here, since it can carry `report.artifactName` (what trivy actually scanned). */
  suiteName: string;
  /**
   * ISO 8601 string for the `<testsuite timestamp="...">` attribute. This module stays pure and
   * never reads the clock itself (a function whose output depends on wall-clock time is a
   * function that fails at midnight, and cannot be pinned in a byte-identical-output test) - the
   * caller (run.ts) is responsible for deciding what moment this represents, e.g. trivy's own
   * `report.createdAt` when present, falling back to when it started the scan otherwise.
   *
   * Format: a full ISO instant (e.g. `2026-07-29T12:34:56.000Z`), not JUnit's other common
   * convention of local-time-without-zone. Nothing in this repository or its installed packages
   * (the `results.publish` timestamp is consumed entirely by the Azure Pipelines agent, which
   * ships in no local package here) pins down which of the two the Azure DevOps publisher
   * actually tolerates, so this is a documented assumption, not a verified fact - if a future
   * run again logs "Timestamp is not available" despite this attribute being present, that
   * format choice is the first thing to revisit.
   */
  timestamp: string;
  /**
   * Seconds for the `<testsuite time="...">` attribute - what fixes the `Run duration 0s` defect.
   * The caller measures this (wall-clock time actually spent on the scan invocation); this
   * module only ever places the number it is given.
   */
  durationSeconds: number;
}

/**
 * Same vocabulary and reasoning as `ReportParser`'s own `CONTROL_CHARS`: this module is a
 * standalone pure function, tested and callable without going through ReportParser, so it
 * cannot rely on findings already being sanitized by the time they arrive here (a caller who
 * skips ReportParser is not hypothetical - a hand-built `NormalizedReport` in a test is exactly
 * that). XML 1.0 forbids most C0 control characters outright (the spec's Char production
 * excludes everything below 0x20 except tab/LF/CR), so a raw one anywhere in this file - not
 * just a newline that could smuggle a second logging command the way it does for Publisher -
 * produces a document Azure DevOps rejects outright. Replacing every C0 control and the DEL
 * byte with a space, then collapsing whitespace, keeps every field on one line and always
 * well-formed.
 */
// eslint-disable-next-line no-control-regex -- intentional: strips C0 controls and the DEL byte.
const CONTROL_CHARS = /[\x00-\x1f\x7f]/g;
const WHITESPACE_RUN = /\s+/g;

/**
 * Neutralizes control characters in one attacker/publisher-controlled field (a finding's title,
 * package name, id, ...: all read out of a scanned artifact, same trust boundary as
 * `ReportParser.sanitizeText`). Deliberately does NOT escape XML metacharacters - that is
 * `escapeXml`'s job, applied once to the fully composed string below - so this can be called on
 * each field individually and the caller can still join sanitized fields with its own literal
 * newlines (see `failureDetail`) without those newlines being stripped back out again.
 */
function sanitizeField(value: unknown): string {
  const text = typeof value === 'string' ? value : String(value ?? '');
  return text.replace(CONTROL_CHARS, ' ').replace(WHITESPACE_RUN, ' ').trim();
}

/**
 * Escapes the five XML metacharacters everywhere this module writes untrusted text, whether
 * that text ends up inside a double-quoted attribute or as element text content. `&` must be
 * replaced first: escaping it after `<`/`>`/etc. would re-escape the literal ampersands those
 * replacements just introduced (turning `&lt;` back into `&amp;lt;`).
 */
function escapeXml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

/** Sanitizes (control characters) then escapes (XML metacharacters) a single untrusted field. */
function xmlSafe(value: unknown): string {
  return escapeXml(sanitizeField(value));
}

/**
 * `[SEVERITY] ID` is what shows in the Tests tab's test name column, and per-CVE history there
 * is keyed on that name staying byte-identical across runs for the same finding - so this must
 * be a pure function of the finding's own fields, never anything time- or run-dependent.
 * `severity` is our own validated enum (never attacker text, see `ENUM_KEYS` in ReportParser),
 * so it is not sanitized; `id` is trivy-reported text and goes through `xmlSafe` like every
 * other field below.
 */
function testCaseName(finding: Finding): string {
  return `[${finding.severity}] ${xmlSafe(finding.id)}`;
}

/**
 * The failure `message` attribute: package, installed version, fixed version (or its absence)
 * and the title, in the same shape `Publisher.logBlockingFindings` already uses for the build
 * log - not a coincidence, it is what a reader of both surfaces will already recognize.
 */
function failureMessage(finding: Finding): string {
  const pkgName = finding.pkgName ? xmlSafe(finding.pkgName) : undefined;
  const installedVersion = finding.installedVersion ? xmlSafe(finding.installedVersion) : undefined;
  const fixedVersion = finding.fixedVersion ? xmlSafe(finding.fixedVersion) : undefined;
  const title = xmlSafe(finding.title);

  const pkg = pkgName ? ` in ${pkgName}${installedVersion ? ` ${installedVersion}` : ''}` : '';
  const fix = fixedVersion ? ` (fixed in ${fixedVersion})` : ' (no fix available)';
  return `${finding.severity}${pkg}${fix}: ${title}`;
}

/**
 * The failure element's body: the longer detail the `message` attribute has no room for.
 * Each field is sanitized individually (`xmlSafe` covers escaping too) and then joined with
 * this function's OWN literal newlines - never the untrusted text's own newlines, which
 * `sanitizeField` already stripped out of every field above. That ordering is what lets this
 * body stay multi-line and readable instead of collapsing to one long space-joined string.
 */
function failureDetail(finding: Finding): string {
  const lines = [
    `Kind: ${xmlSafe(finding.kind)}`,
    `Target: ${xmlSafe(finding.target)}`,
    finding.pkgName ? `Package: ${xmlSafe(finding.pkgName)}` : undefined,
    finding.installedVersion ? `Installed version: ${xmlSafe(finding.installedVersion)}` : undefined,
    `Fixed version: ${finding.fixedVersion ? xmlSafe(finding.fixedVersion) : 'none available'}`,
    finding.location ? `Location: ${xmlSafe(finding.location)}` : undefined,
    '',
    xmlSafe(finding.title),
  ].filter((line): line is string => line !== undefined);
  return lines.join('\n');
}

/**
 * `classname` groups testcases in the Tests tab. Trivy's own finding `kind` (vulnerability,
 * secret, misconfiguration, license) is used rather than `target`: it is a small, stable,
 * four-value vocabulary a team can filter on across every scan in the collection ("show me
 * every failing secret"), whereas `target` is effectively unique per scanned artifact and
 * would fragment the grouping into one bucket per image/path instead of collapsing anything.
 * `kind` is our own literal (see `ENUM_KEYS` in ReportParser), not attacker text, but it is
 * still routed through `xmlSafe` for uniformity with every other attribute built here.
 */
function testCaseClassname(finding: Finding): string {
  return xmlSafe(finding.kind);
}

function buildTestCase(finding: Finding): string {
  const name = testCaseName(finding);
  const classname = testCaseClassname(finding);
  const message = failureMessage(finding);
  // failureDetail already escapes each field it interpolates (via xmlSafe) before joining them
  // with its own literal newlines - escaping the composed result a second time here would
  // double-escape every entity it just produced (e.g. "&lt;" becoming "&amp;lt;").
  const detail = failureDetail(finding);

  // Deliberately hardcoded, not a share of the suite's durationSeconds: trivy reports every
  // finding from a single parsed JSON document, not from an individually-timed check, so there
  // is no real per-finding duration to distribute - splitting the suite total across testcases
  // would manufacture a precision this task never measured. The suite-level `time` (see
  // buildJUnitXml below) is the honest number; this one stays 0 for every testcase.
  return (
    `  <testcase name="${name}" classname="${classname}" time="0">\n` +
    `    <failure message="${message}">${detail}</failure>\n` +
    `  </testcase>\n`
  );
}

/**
 * Converts an already-parsed `NormalizedReport` into a JUnit XML document suitable for
 * `results.publish`. Pure and hub-free: no filesystem, no docker, no Azure Pipelines API - the
 * caller (run.ts) is responsible for writing the returned string to disk and publishing it.
 *
 * One `<testcase>` per finding, every one of them a `<failure>`: that is the whole point of
 * this feature (see the README section on publishing test results) - a report with findings is
 * meant to show red in the Tests tab even when the gate itself passed (failOn threshold not
 * met, or disabled). A report with zero findings would otherwise produce an empty `<testsuite>`,
 * which several JUnit consumers (and Azure DevOps itself) render as "no tests ran" rather than
 * "all clear" - so that case gets a single synthetic passing testcase instead.
 */
export function buildJUnitXml(report: NormalizedReport, options: JUnitReportOptions): string {
  const suiteName = xmlSafe(options.suiteName);
  // xmlSafe here for the same reason as every other field in this module: run.ts may pass
  // trivy's own report.createdAt through unchanged, and that is attacker/publisher-controlled
  // text (same trust boundary as artifactName), not a value this module minted itself.
  const timestamp = xmlSafe(options.timestamp);
  const time = options.durationSeconds;
  const findings = report.findings;

  if (findings.length === 0) {
    return (
      '<?xml version="1.0" encoding="UTF-8"?>\n' +
      `<testsuite name="${suiteName}" tests="1" failures="0" time="${time}" timestamp="${timestamp}">\n` +
      `  <testcase name="No findings" classname="${suiteName}" time="0"/>\n` +
      '</testsuite>\n'
    );
  }

  const testcases = findings.map(buildTestCase).join('');
  return (
    '<?xml version="1.0" encoding="UTF-8"?>\n' +
    `<testsuite name="${suiteName}" tests="${findings.length}" failures="${findings.length}" time="${time}" timestamp="${timestamp}">\n` +
    testcases +
    '</testsuite>\n'
  );
}
