import * as fs from 'fs';
import * as path from 'path';
import { parseTrivyReport, parseVersion, TrivyReportParseError } from '../ReportParser';

const fixture = (name: string): string =>
  fs.readFileSync(path.join(__dirname, '../../../test/fixtures/trivy', name), 'utf8');

const meta = { scanType: 'image' as const, target: 'app:1.4.2', runner: { alias: 'baseline', image: 'registry.example.com/trivy:0.58.1' } };

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

  it('stamps the normalized schema version', () => {
    const report = parseTrivyReport(fixture('image-vulns.json'), meta);
    expect(report.schemaVersion).toBe(1);
  });

  // Regression guard: the fixture's ArtifactName happens to equal meta.target, so a bug that
  // always falls back to meta.target instead of reading document.ArtifactName would still
  // pass a test that only checks against that fixture. This uses an ArtifactName that is
  // deliberately different from meta.target so the two cannot be confused.
  it('carries the artifact name trivy reported even when it differs from the requested target', () => {
    const raw = JSON.stringify({
      SchemaVersion: 2,
      CreatedAt: '2026-07-28T09:12:44.512Z',
      ArtifactName: 'app@sha256:deadbeefcafe',
      Results: [],
    });
    const report = parseTrivyReport(raw, meta);
    expect(report.artifactName).toBe('app@sha256:deadbeefcafe');
    expect(report.artifactName).not.toBe(meta.target);
    expect(report.createdAt).toBe('2026-07-28T09:12:44.512Z');
  });

  // Real trivy (confirmed against 0.72.0) omits the "Results" key entirely when a scan finds
  // nothing, rather than emitting "Results": []. This must parse to a valid empty report, not
  // an error — see the "recognizes a Results-less document" describe block below for the full
  // set of empty/malformed/unrecognizable cases.
  it('returns an empty report with zeroed counts when nothing was found (no Results key)', () => {
    const report = parseTrivyReport(fixture('empty-no-results-key.json'), meta);
    expect(report.findings).toEqual([]);
    expect(report.counts.CRITICAL).toBe(0);
    expect(report.artifactName).toBe('.');
  });

  // Older trivy versions and some scan types do emit "Results": [] for a scan that finds
  // nothing; both shapes must parse identically to zero findings.
  it('returns an empty report with zeroed counts when nothing was found ("Results": [])', () => {
    const report = parseTrivyReport(fixture('empty-results-array.json'), meta);
    expect(report.findings).toEqual([]);
    expect(report.counts.CRITICAL).toBe(0);
    expect(report.artifactName).toBe('app:1.4.3');
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
    expect(() => parseTrivyReport('{not json', meta)).toThrow(/registry.example.com\/trivy:0.58.1/);
  });

  it('rejects a json document that is not a trivy report', () => {
    expect(() => parseTrivyReport('{"hello":"world"}', meta)).toThrow(/Results/);
  });
});

describe('a Results-less document that is still recognisably a trivy report', () => {
  // Trivy omits "Results" entirely rather than emitting an empty array when a scan finds
  // nothing. SchemaVersion is trusted as the strongest signal that this is genuinely a trivy
  // document: it has been present in every trivy report since the current schema was
  // introduced, and no other tool has a reason to emit a field with that exact name. It alone
  // is sufficient. ArtifactName/ArtifactType (trivy's own field names for what was scanned and
  // how) are trusted only together, as a fallback for a hypothetical schema that omits
  // SchemaVersion — neither is trusted alone, since either one in isolation is just an
  // ordinary string that some unrelated JSON document could coincidentally also have.
  it('parses to zero findings with all counts and kindCounts zero when only SchemaVersion is present', () => {
    const raw = JSON.stringify({ SchemaVersion: 2, ArtifactName: 'app@sha256:deadbeefcafe' });
    const report = parseTrivyReport(raw, meta);
    expect(report.findings).toEqual([]);
    expect(report.counts).toEqual({ UNKNOWN: 0, LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 });
    expect(report.kindCounts).toEqual({
      vulnerability: 0,
      secret: 0,
      misconfiguration: 0,
      license: 0,
    });
    expect(report.artifactName).toBe('app@sha256:deadbeefcafe');
  });

  it('parses to zero findings when ArtifactName and ArtifactType are present but SchemaVersion is not', () => {
    const raw = JSON.stringify({ ArtifactName: '.', ArtifactType: 'filesystem' });
    const report = parseTrivyReport(raw, meta);
    expect(report.findings).toEqual([]);
  });

  it('does not accept ArtifactName alone, without ArtifactType or SchemaVersion, as recognisable', () => {
    const raw = JSON.stringify({ ArtifactName: '.' });
    expect(() => parseTrivyReport(raw, meta)).toThrow(TrivyReportParseError);
  });
});

describe('rejects documents that are not a recognisable trivy report', () => {
  it('rejects Results as a string instead of treating it as empty or valid', () => {
    const raw = JSON.stringify({ SchemaVersion: 2, Results: 'nothing to see here' });
    expect(() => parseTrivyReport(raw, meta)).toThrow(TrivyReportParseError);
  });

  it('rejects Results as a number instead of treating it as empty or valid', () => {
    const raw = JSON.stringify({ SchemaVersion: 2, Results: 42 });
    expect(() => parseTrivyReport(raw, meta)).toThrow(TrivyReportParseError);
  });

  it('names the top-level keys that were present when nothing marks the document as trivy output', () => {
    let error: Error | undefined;
    try {
      parseTrivyReport('{"hello":"world","foo":1}', meta);
    } catch (e) {
      error = e as Error;
    }
    expect(error).toBeInstanceOf(TrivyReportParseError);
    expect(error?.message).toContain('hello');
    expect(error?.message).toContain('foo');
  });

  // The rejected document's raw text is attacker/publisher-controlled in exactly the same way
  // a finding's PkgName is (a malicious or broken scan target could produce anything as stdout),
  // and this message reaches the same build log parsed line-by-line for Azure Pipelines logging
  // commands. It must go through the same sanitisation as every other trivy-controlled string
  // in this module. JSON permits literal newlines as formatting whitespace between tokens (not
  // inside a string value), so pretty-printed, hostile-looking JSON like this parses just fine
  // and reaches the raw-text preview in the rejection message with its newlines intact — unless
  // that preview is sanitized the same way findings are.
  it('cannot inject a logging command into the build log via the rejection message', () => {
    const raw = '{\n  "hello": "world",\n  "note": "##vso[task.complete result=Succeeded]"\n}';
    let error: Error | undefined;
    try {
      parseTrivyReport(raw, meta);
    } catch (e) {
      error = e as Error;
    }
    expect(error).toBeInstanceOf(TrivyReportParseError);
    expect(error?.message).not.toContain('\n');
    expect(error?.message).not.toContain('\r');
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
});

describe('malformed and hostile trivy output', () => {
  // The module's whole contract is "every exit is a valid report or a TrivyReportParseError."
  // JSON.parse('null') does not throw, so without an explicit shape guard the very next
  // property access (`document.Results`) throws a raw, unactionable TypeError instead.
  it('rejects a bare JSON null document with an actionable error instead of a raw TypeError', () => {
    expect(() => parseTrivyReport('null', meta)).toThrow(TrivyReportParseError);
    expect(() => parseTrivyReport('null', meta)).toThrow(/registry.example.com\/trivy:0.58.1/);
    expect(() => parseTrivyReport('null', meta)).toThrow(/app:1.4.2/);
  });

  it('rejects a JSON array document the same way, since it also has no Results property', () => {
    expect(() => parseTrivyReport('[1,2,3]', meta)).toThrow(TrivyReportParseError);
  });

  // One malformed entry inside Results should degrade like an unrecognized severity does —
  // not take down parsing of an otherwise valid report.
  it('treats a null entry in Results as contributing no findings instead of crashing', () => {
    const report = parseTrivyReport('{"Results":[null]}', meta);
    expect(report.findings).toEqual([]);
  });

  it('coerces a non-string PkgName instead of crashing the sanitizer', () => {
    const raw = JSON.stringify({
      Results: [
        {
          Target: 'app:1.4.2',
          Vulnerabilities: [
            { VulnerabilityID: 'CVE-X', PkgName: 42, InstalledVersion: '1.0', Severity: 'HIGH', Title: 'x' },
          ],
        },
      ],
    });
    const report = parseTrivyReport(raw, meta);
    expect(report.findings[0].pkgName).toBe('42');
  });

  it('coerces a non-string Severity instead of crashing the severity mapper', () => {
    const raw = JSON.stringify({
      Results: [{ Target: 't', Vulnerabilities: [{ VulnerabilityID: 'CVE-X', Severity: 7, Title: 'x' }] }],
    });
    expect(() => parseTrivyReport(raw, meta)).not.toThrow();
    const report = parseTrivyReport(raw, meta);
    expect(report.findings[0].severity).toBe('UNKNOWN');
  });

  it('coerces an object Title instead of crashing', () => {
    const raw = JSON.stringify({
      Results: [{ Target: 't', Vulnerabilities: [{ VulnerabilityID: 'CVE-X', Severity: 'HIGH', Title: {} }] }],
    });
    expect(() => parseTrivyReport(raw, meta)).not.toThrow();
    expect(typeof parseTrivyReport(raw, meta).findings[0].title).toBe('string');
  });

  it('coerces a falsy numeric Title (0) instead of dropping it', () => {
    const raw = JSON.stringify({
      Results: [{ Target: 't', Vulnerabilities: [{ VulnerabilityID: 'CVE-X', Severity: 'HIGH', Title: 0 }] }],
    });
    const report = parseTrivyReport(raw, meta);
    expect(report.findings[0].title).toBe('0');
  });

  it('ignores a Vulnerabilities container that is not an array instead of crashing', () => {
    const raw = JSON.stringify({ Results: [{ Target: 't', Vulnerabilities: 42 }] });
    expect(() => parseTrivyReport(raw, meta)).not.toThrow();
    expect(parseTrivyReport(raw, meta).findings).toEqual([]);
  });

  // The most dangerous of the malformed-input cases: a string does not crash a `for...of`
  // loop, so without an explicit Array.isArray guard each character silently becomes a fake
  // finding with id 'UNKNOWN' — three findings out of "abc" that were never in the scan.
  it('ignores a Vulnerabilities container that is a string instead of iterating its characters', () => {
    const raw = JSON.stringify({ Results: [{ Target: 't', Vulnerabilities: 'abc' }] });
    const report = parseTrivyReport(raw, meta);
    expect(report.findings).toEqual([]);
  });
});

describe('unrecognized severities', () => {
  // This is the module's headline design decision — the one with a four-line comment
  // explaining why it deliberately differs from shared/severity.ts — and it had no test.
  it('degrades an unrecognized severity string to UNKNOWN rather than throwing', () => {
    const raw = JSON.stringify({
      Results: [{ Target: 't', Vulnerabilities: [{ VulnerabilityID: 'CVE-X', Severity: 'BOGUS', Title: 'x' }] }],
    });
    expect(() => parseTrivyReport(raw, meta)).not.toThrow();
    expect(parseTrivyReport(raw, meta).findings[0].severity).toBe('UNKNOWN');
  });

  // UNKNOWN ranks lowest and FailOn excludes it, so a finding degraded this way is
  // structurally incapable of failing a build. That must be visible to the caller, not silent.
  it('exposes an unrecognized severity label on the report so the caller can warn', () => {
    const raw = JSON.stringify({
      Results: [{ Target: 't', Vulnerabilities: [{ VulnerabilityID: 'CVE-X', Severity: 'BOGUS', Title: 'x' }] }],
    });
    const report = parseTrivyReport(raw, meta);
    expect(report.unrecognizedSeverities).toEqual(['BOGUS']);
  });

  it('does not report a recognized severity as unrecognized', () => {
    const report = parseTrivyReport(fixture('image-vulns.json'), meta);
    expect(report.unrecognizedSeverities).toEqual([]);
  });

  // The label is attacker-influenced (it comes straight from trivy's Severity field, which for
  // a filesystem/repository scan traces back to scanned content), so it goes through the same
  // sanitizer as everything else before being exposed.
  it('sanitizes control characters out of a collected unrecognized severity label', () => {
    const raw = JSON.stringify({
      Results: [
        {
          Target: 't',
          Vulnerabilities: [{ VulnerabilityID: 'CVE-X', Severity: 'BOGUS\n##vso[task.complete result=Succeeded]', Title: 'x' }],
        },
      ],
    });
    const report = parseTrivyReport(raw, meta);
    expect(report.unrecognizedSeverities).toHaveLength(1);
    expect(report.unrecognizedSeverities[0]).not.toContain('\n');
  });
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

  it('trims leading and trailing whitespace rather than just collapsing internal runs', () => {
    const raw = JSON.stringify({
      Results: [{ Target: 't', Vulnerabilities: [{ VulnerabilityID: 'CVE-X', Severity: 'HIGH', Title: '   padded title   ' }] }],
    });
    const report = parseTrivyReport(raw, meta);
    expect(report.findings[0].title).toBe('padded title');
  });

  it('sanitizes control characters out of the vulnerability id', () => {
    const raw = JSON.stringify({
      Results: [
        { Target: 't', Vulnerabilities: [{ VulnerabilityID: 'CVE-X\n##vso[task.complete result=Succeeded]', Severity: 'HIGH', Title: 'x' }] },
      ],
    });
    const report = parseTrivyReport(raw, meta);
    expect(report.findings[0].id).toBe('CVE-X ##vso[task.complete result=Succeeded]');
  });

  it('sanitizes control characters out of the finding target', () => {
    const raw = JSON.stringify({
      Results: [
        { Target: 'app\n##vso[task.complete result=Succeeded]', Vulnerabilities: [{ VulnerabilityID: 'CVE-X', Severity: 'HIGH', Title: 'x' }] },
      ],
    });
    const report = parseTrivyReport(raw, meta);
    expect(report.findings[0].target).toBe('app ##vso[task.complete result=Succeeded]');
  });

  it('sanitizes control characters out of installedVersion', () => {
    const raw = JSON.stringify({
      Results: [
        {
          Target: 't',
          Vulnerabilities: [
            { VulnerabilityID: 'CVE-X', Severity: 'HIGH', Title: 'x', InstalledVersion: '1.0\n##vso[task.complete result=Succeeded]' },
          ],
        },
      ],
    });
    const report = parseTrivyReport(raw, meta);
    expect(report.findings[0].installedVersion).toBe('1.0 ##vso[task.complete result=Succeeded]');
  });

  it('sanitizes control characters out of fixedVersion', () => {
    const raw = JSON.stringify({
      Results: [
        {
          Target: 't',
          Vulnerabilities: [
            { VulnerabilityID: 'CVE-X', Severity: 'HIGH', Title: 'x', FixedVersion: '1.1\n##vso[task.complete result=Succeeded]' },
          ],
        },
      ],
    });
    const report = parseTrivyReport(raw, meta);
    expect(report.findings[0].fixedVersion).toBe('1.1 ##vso[task.complete result=Succeeded]');
  });

  it('sanitizes control characters out of a secret location built from a hostile target', () => {
    const raw = JSON.stringify({
      Results: [
        {
          Target: 'deploy\n##vso[task.complete result=Succeeded]/values.yaml',
          Secrets: [{ RuleID: 'aws-access-key-id', Severity: 'CRITICAL', Title: 'AWS Access Key ID', StartLine: 14 }],
        },
      ],
    });
    const report = parseTrivyReport(raw, meta);
    const secret = report.findings[0];
    expect(secret.location).not.toContain('\n');
    expect(secret.target).not.toContain('\n');
    expect(secret.location).toBe('deploy ##vso[task.complete result=Succeeded]/values.yaml:14');
  });

  it('treats a StartLine of 0 as present rather than falling back to the bare target', () => {
    const raw = JSON.stringify({
      Results: [{ Target: 'deploy/values.yaml', Secrets: [{ RuleID: 'r', Severity: 'HIGH', Title: 't', StartLine: 0 }] }],
    });
    const report = parseTrivyReport(raw, meta);
    expect(report.findings[0].location).toBe('deploy/values.yaml:0');
  });

  it('replaces ESC, NUL and BEL with a space rather than passing ANSI/control bytes into the log', () => {
    const raw = JSON.stringify({
      Results: [{ Target: 't', Vulnerabilities: [{ VulnerabilityID: 'CVE-X', Severity: 'HIGH', Title: 'a\x1b[31mb\x00c\x07d' }] }],
    });
    const report = parseTrivyReport(raw, meta);
    expect(report.findings[0].title).toBe('a [31mb c d');
  });

  it('replaces U+0085 (NEL) with a space, since JS \\s does not match it on its own', () => {
    const raw = JSON.stringify({
      Results: [{ Target: 't', Vulnerabilities: [{ VulnerabilityID: 'CVE-X', Severity: 'HIGH', Title: 'ab' }] }],
    });
    const report = parseTrivyReport(raw, meta);
    expect(report.findings[0].title).toBe('a b');
  });
});

describe('sanitizes report-level and version fields', () => {
  it('sanitizes control characters out of artifactName', () => {
    const raw = JSON.stringify({
      ArtifactName: 'app\n##vso[task.complete result=Succeeded]',
      Results: [],
    });
    const report = parseTrivyReport(raw, meta);
    expect(report.artifactName).toBe('app ##vso[task.complete result=Succeeded]');
  });

  it('sanitizes control characters out of createdAt', () => {
    const raw = JSON.stringify({
      CreatedAt: '2026-07-28\n##vso[task.complete result=Succeeded]',
      Results: [],
    });
    const report = parseTrivyReport(raw, meta);
    expect(report.createdAt).toBe('2026-07-28 ##vso[task.complete result=Succeeded]');
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

  // The Publisher writes trivyVersion straight into a log line via its own sanitizer, which
  // assumes a string. Trivy's own version output is decoration and outside our data format,
  // so a garbled response should degrade like everything else here, not crash a scan that
  // otherwise succeeded.
  it('coerces a non-string Version instead of returning a value the Publisher cannot sanitize', () => {
    expect(parseVersion(JSON.stringify({ Version: 42 }))).toEqual({ trivyVersion: '42' });
  });

  it('sanitizes control characters out of the trivy version string', () => {
    const raw = JSON.stringify({ Version: '0.58.1\n##vso[task.complete result=Succeeded]' });
    expect(parseVersion(raw).trivyVersion).toBe('0.58.1 ##vso[task.complete result=Succeeded]');
  });

  it('coerces a non-string database UpdatedAt instead of crashing downstream', () => {
    expect(parseVersion(JSON.stringify({ VulnerabilityDB: { UpdatedAt: 42 } }))).toEqual({
      dbUpdatedAt: '42',
    });
  });

  it('sanitizes control characters out of the database updated-at timestamp', () => {
    const raw = JSON.stringify({
      VulnerabilityDB: { UpdatedAt: '2026-07-28\n##vso[task.complete result=Succeeded]' },
    });
    expect(parseVersion(raw).dbUpdatedAt).toBe('2026-07-28 ##vso[task.complete result=Succeeded]');
  });
});
