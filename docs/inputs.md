# Task inputs reference

Every input `TrivyScan@1` accepts, derived from `src/task/task.json` (the declared
inputs and pick lists), `src/shared/types.ts` (`TaskInputs`, `OverridableField`),
`src/task/inputs.ts` (parsing, accepted values, exact error wording) and
`src/task/ConfigResolver.ts` (defaults and precedence). See the
[examples](../examples) directory for complete pipelines using many of these
together.

## Precedence

Every resolved field comes from one of three places, tried in this order:

1. **Built-in default**, hardcoded in `ConfigResolver.ts`. This is the fallback of
   last resort for every optional field.
2. **The collection's `defaults` document** (Collection Settings > Trivy Scanner >
   Defaults tab), for the fields `DefaultsConfig` declares
   (`severities`, `scanners`, `failOn`, `ignoreUnfixed`, `skipDbUpdate`,
   `timeoutMinutes`; `runner` indirectly, via the catalog's `isDefault` flag).
   Fields with no `DefaultsConfig` counterpart at all (`ignoreFile`,
   `useDockerSocket`, `extraTrivyArgs`) skip straight from the built-in default to
   the pipeline input — an administrator can only allow or deny them, never set a
   collection-wide value for them.
3. **The pipeline's own task input**, but only for the ten fields
   `OverridableField` names, and only when the collection's Policy tab
   (`allowOverrides`) permits that specific field. `allowOverrides` omitted from the
   `defaults` document entirely means every one of those ten fields may be set from
   a pipeline; an empty list means none may — these are opposite meanings, not two
   spellings of the same thing.

**A locked field is rejected, not silently downgraded.** If a pipeline sets a field
the Policy tab does not permit, the task does not quietly substitute the
collection's value and continue — the whole run fails immediately, before the scan
starts, with an error naming every offending field and the value the collection
would have enforced, for example:

```
The pipeline sets "failOn", but the collection policy does not allow overriding it.
The collection sets failOn to "HIGH". Overridable fields: severities, scanners,
ignoreUnfixed, timeoutMinutes, skipDbUpdate, useDockerSocket, extraTrivyArgs,
ignoreFile. Change the value in Collection Settings > Trivy Scanner.
```

Fields outside `OverridableField` (`scanType`, `target`, `formats`, `generateSbom`,
`publishArtifact`, `publishTestResults`, `sourceTransfer`, `workingDirectory`,
`targetRegistryConnection`, `configConnection`) are never subject to this check at
all: a pipeline's value for them always applies, with no Policy-tab involvement.

## Where the vulnerability database comes from

The vulnerability database is not a task input, and not part of the precedence
chain above — no pipeline can name one directly, only indirectly via `runner`.
Its own resolution (`ConfigResolver.ts`'s `resolveDatabase`) is a two-step
fallback, tried for whichever runner `runner` above resolves to:

1. **The runner's linked database.** If the selected runner names a `database`
   (`RunnerConfig.database`, an alias into the collection's `databases`
   catalogue — Collection Settings > Trivy Scanner > Databases), that entry's
   `repository`/`javaRepository`/`registryUsername`/`registryPassword` are used.
   This is the only path a configuration created after the catalogue existed
   should use.
2. **The collection's deprecated `defaults` fields**, `dbRepository`/
   `javaDbRepository`/`dbRegistryUsername`/`dbRegistryPassword`, used only when
   the selected runner has no `database` linked at all. Every scan that takes
   this fallback logs a warning naming the runner, so an administrator can see
   which runners still need migrating (see the README's "Migrating to the
   database catalogue" section). If the runner has no `database` and `defaults`
   has no `dbRepository` either, the build fails with a `DatabaseNotFoundError`
   naming the runner and pointing at the admin hub.

A database belongs to the runner that uses it, not to the collection as a
whole, because a runner backed by a custom trivy image may ship with, and
expect, its own database instead of the official one — this is why there is no
"built-in default" step here the way there is for `severities` or `failOn`
above: an unconfigured collection has no database at all, by design, and must
fail loudly rather than guess at one.

## Which inputs are policy-gated, and why

**Gated** (member of `OverridableField`, subject to the Policy tab):
`runner`, `severities`, `scanners`, `failOn`, `ignoreUnfixed`, `timeoutMinutes`,
`skipDbUpdate`, `useDockerSocket`, `extraTrivyArgs`, `ignoreFile`.

These are exactly the fields that determine what a scan finds, how strict the gate
is, or what it can quietly bypass. `severities` and `failOn` are the gate itself;
`scanners`, `ignoreUnfixed`, `skipDbUpdate` and `timeoutMinutes` change what trivy
actually reports or whether it completes a meaningful scan at all; `runner` chooses
which image and vulnerability database run. `extraTrivyArgs`, `ignoreFile` and
`useDockerSocket` are gated for a sharper reason: left open, each is a way for a
pipeline to defeat the *other* locks even if `severities`/`failOn`/`scanners` are
themselves locked down — `extraTrivyArgs` could otherwise try to slip in a
competing trivy flag, `ignoreFile` could suppress the exact findings the gate is
supposed to catch, and `useDockerSocket` hands the scan container a privileged path
to the host's docker daemon that has nothing to do with the scan itself.

**Not gated, deliberately:**

- `scanType` and `target` are not gated because they *are* the scan: an
  administrator locking them would mean the collection dictates what every
  pipeline scans, which defeats the point of a per-pipeline task.
- `formats`, `generateSbom`, `publishArtifact` and `publishTestResults` change what
  gets *published*, never what gets found or what the gate decides — there is no
  gate-integrity reason to restrict a reporting convenience, so any pipeline may
  always set them directly (see `TaskInputs.publishTestResults`'s doc comment in
  `src/shared/types.ts` for this reasoning in the source).
- `sourceTransfer` describes the agent's own topology (does its docker daemon share
  a filesystem with it?), not a security policy — a collection can freely mix agent
  pools with different topologies, so this is left to the pipeline (see
  `TaskInputs.sourceTransfer`'s doc comment).
- `workingDirectory`, `targetRegistryConnection` and `configConnection` are not
  members of `OverridableField` either. The source gives no explicit rationale for
  `workingDirectory` specifically (it is simply absent from the list); the two
  connection inputs select *which credential* the task uses (to pull the scanned
  image, or to read the collection's own settings), which is an orthogonal concern
  from the severity/gate policy `allowOverrides` protects.

## Invariants no pipeline input can override

Two things are fixed inside the task and cannot be reached by any input, gated or
not, because the gate depends on them staying fixed:

- **Trivy always runs with `--exit-code 0`.** A non-zero docker exit code is always
  treated as an infrastructure failure (docker itself could not run the container),
  never "the scan found something" — the build gate is computed entirely from the
  parsed JSON report, not from trivy's own exit code, so there is no input for this
  and none is needed.
- **The scan that produces the gate's report always runs with `--format json
  --output <path>`**, fixed to a path this task controls. The `formats` input
  never affects this run; it only selects which *additional* outputs (the table
  log, an extra SARIF run) are produced alongside it. Listing or omitting `json` in
  `formats` has no effect.

Both are re-asserted a second time, after any `extraTrivyArgs` tokens are appended,
because on trivy's CLI the last occurrence of a flag wins — so even if a value
slipped past the reserved-flag check below, it could not actually take effect.

## Reserved trivy flags in `extraTrivyArgs`

`extraTrivyArgs` is rejected outright — the build fails naming the flag — if it
contains any of these (`src/task/DockerCommand.ts`, `RESERVED_TRIVY_FLAGS`):

| Flag | Use this input instead |
|---|---|
| `--format`, `-f` | (no input — the report format is fixed so the parser can read it back) |
| `--output`, `-o` | (no input — the report destination is fixed so the task can read the file back) |
| `--exit-code` | (no input — the gate is computed from the parsed report, not trivy's exit code) |
| `--severity`, `-s` | `severities` |
| `--scanners` | `scanners` |
| `--ignore-unfixed` | `ignoreUnfixed` |
| `--skip-db-update` | `skipDbUpdate` |
| `--ignorefile` | `ignoreFile` |
| `--timeout` | `timeoutMinutes` |

Both the two-token (`--flag value`) and one-token (`--flag=value`) spellings are
checked. `extraTrivyArgs` is parsed with shell-like quoting (`splitArgs` in
`src/shared/args.ts`: whitespace separates tokens, single/double quotes keep a
token together with the quotes stripped) but has no shell semantics at all — no
variable expansion, no backslash escaping. An unterminated quote fails with
`Unterminated quote in arguments at position <n>.`

## Inputs

| Name | Type | Accepted values | Gated? |
|---|---|---|---|
| `scanType` | pickList | `image`, `filesystem`, `repository`, `config`, `sbom` | No |
| `target` | string, required | any string | No |
| `runner` | string | a runner alias from the catalog | Yes |
| `severities` | string | comma list of `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`, `UNKNOWN` | Yes |
| `scanners` | string | comma list of `vuln`, `secret`, `misconfig`, `license` | Yes |
| `failOn` | string | `none`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` | Yes |
| `ignoreUnfixed` | boolean | `true`, `false` | Yes |
| `ignoreFile` | string | path relative to the sources directory | Yes |
| `formats` | string | comma list of `table`, `json`, `sarif` | No |
| `generateSbom` | pickList | `off`, `cyclonedx`, `spdx-json` | No |
| `publishArtifact` | boolean | `true`, `false` | No |
| `publishTestResults` | boolean | `true`, `false` | No |
| `targetRegistryConnection` | connectedService:dockerregistry | name of a Docker Registry service connection | No |
| `configConnection` | connectedService:Generic | name of a Generic service connection | No |
| `useDockerSocket` | boolean | `true`, `false` | Yes |
| `sourceTransfer` | pickList | `mount`, `copy` | No |
| `skipDbUpdate` | boolean | `true`, `false` | Yes |
| `timeoutMinutes` | string (numeric) | a positive number | Yes |
| `extraTrivyArgs` | string | free-form trivy CLI arguments (reserved flags excluded, see above) | Yes |
| `workingDirectory` | string | path relative to the sources directory | No |

Every value in the "Accepted values" column above is matched case-insensitively and
normalized to lowercase (or to trivy's own uppercase severity spelling), except
`target`, which is used verbatim.

### `scanType`

Required. Which kind of scan to run: `image` (a container image reference),
`filesystem` (a path on disk), `repository` (a git repository, local or remote),
`config` (IaC misconfiguration scanning of a directory) or `sbom` (scan an
*existing* SBOM file for vulnerabilities — not to be confused with `generateSbom`
below, which *produces* an SBOM as an output of an `image`/`filesystem` scan; these
are unrelated features that happen to share the word "SBOM").

Omitted: `task.json` declares a `defaultValue` of `image` for this input, and
`inputs.ts` also defaults it to `image` in code — the one deliberate exception to
the rule that no other input carries a `task.json` default (see below).

Not policy-gated: it defines what is being scanned, which is the reason the task
exists; an administrator cannot lock every pipeline in the collection to one scan
type.

### `target`

Required. An image reference for `scanType: image`, otherwise a path relative to
the sources directory (or, for `repository`, a repository location trivy
understands). Not trimmed, unlike every other free-text input here — a stray
leading/trailing space is surfaced as a mistake (e.g. a scan of the wrong path)
rather than silently corrected, since `target` is also echoed into report and
artifact naming.

Omitted: rejected — `Input "target" is required: pass an image reference or a
path to scan.`

Not policy-gated, for the same reason as `scanType`.

### `runner`

Optional. The alias of a runner from the collection's catalog (Collection Settings
> Trivy Scanner > Runners). Whitespace-trimmed; an empty string is treated the same
as omitting it.

Omitted: the catalog's single enabled runner marked `isDefault: true` is used. If
no runner is marked default (or the default one is disabled), the build fails with
a `RunnerNotFoundError` naming the problem and pointing at the admin hub.

Gated: if the Policy tab does not permit `runner` and a pipeline names one anyway,
the build fails and the error reports which runner the collection would have used
instead.

The selected runner also decides which vulnerability database is used — there is
no separate task input for it. See "Where the vulnerability database comes from"
below.

### `severities`

Optional. Comma-separated list of `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`, `UNKNOWN`
(any case; `UNKNOWN` is valid here, unlike in `failOn`). Filters which findings
trivy reports *at all* — a severity left out never appears in the report, the log,
the JSON attachment, the JUnit results or the gate, not just excluded from failing
the build.

Omitted: falls back to the collection's `defaults.severities`, or, if that is also
unset, the built-in default `CRITICAL,HIGH`.

Gated. An empty or blank value is rejected rather than silently becoming "no
filter": `Input "severities" has value "<raw>": No severities found in "<raw>".`
An unrecognized entry fails with `Input "severities" has value "<raw>": Unknown
severity "<value>". Allowed values: UNKNOWN, LOW, MEDIUM, HIGH, CRITICAL.`

### `scanners`

Optional. Comma-separated list of `vuln`, `secret`, `misconfig`, `license` (any
case). Has no effect at all for `scanType: config`, since `trivy config` always
runs the misconfiguration scanner only and has no `--scanners` flag to set.

Omitted: falls back to the collection's `defaults.scanners`, or the built-in
default `vuln,secret`.

Gated. Blank fails with `Input "scanners" must contain at least one value, got
"<raw>".` An unrecognized entry fails with `Input "scanners" has value "<part>".
Allowed values: vuln, secret, misconfig, license.`

### `failOn`

Optional. The severity threshold at or above which the build fails, or the literal
`none` to disable the gate entirely. Accepts `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` —
**not** `UNKNOWN`, which is rejected deliberately: `UNKNOWN` ranks below every
real severity, so allowing it as a threshold would make it the *strictest*
possible setting (failing on every finding, including ones trivy could not score),
the opposite of what a lowest-severity-sounding value suggests. `UNKNOWN` remains a
perfectly valid *finding* severity (usable in `severities`); it is only meaningless
as a `failOn` threshold.

Omitted: falls back to the collection's `defaults.failOn`, or the built-in default
`CRITICAL`.

Gated. `UNKNOWN` fails with: `Input "failOn" cannot be "UNKNOWN": it is a valid
finding severity but a meaningless threshold, since it would fail the build on
every finding, including ones Trivy could not score. Use "none" to disable the
gate, or one of: LOW, MEDIUM, HIGH, CRITICAL.` Any other unrecognized value fails
with `Input "failOn" has value "<raw>". Allowed values: none, LOW, MEDIUM, HIGH,
CRITICAL.`

### `ignoreUnfixed`

Optional boolean. When true, passes `--ignore-unfixed` to trivy, dropping findings
that have no fixed version available from the report entirely.

Omitted: falls back to the collection's `defaults.ignoreUnfixed`, or the built-in
default `false`.

Gated. The task distinguishes "not set at all" from an explicit `false` by
checking whether the pipeline provided the input before reading its boolean value
(`getBoolInput` alone returns `false` for both cases, which would otherwise mask an
administrator's default of `true`).

### `ignoreFile`

Optional. Path to a `.trivyignore` file, relative to the sources directory (not
absolute) — for example `.trivyignore` or `config/.trivyignore`. Trimmed of
surrounding whitespace.

Omitted: no ignore file is passed to trivy at all. There is no collection-level
default value for this field — an administrator can only allow or deny the
pipeline from setting one, never supply a collection-wide ignore file through the
Defaults tab (`DefaultsConfig` has no `ignoreFile` field).

Gated. A value that resolves outside the mounted sources directory (e.g. an
attempted `../` escape) is rejected rather than silently clamped: `"ignoreFile"
value "<value>" escapes the mounted workspace (resolves to "<resolved>"). Use a
path relative to the sources root.`

### `formats`

Optional. Comma-separated list of `table`, `json`, `sarif` (any case) — which
*additional* outputs to produce alongside the JSON report the gate always
requires (see "Invariants" above). `table` prints a findings table to the build
log; `sarif` runs one extra trivy invocation to produce a SARIF file, published to
the `CodeAnalysisLogs` artifact. Listing or omitting `json` here has no effect,
since that run always happens regardless.

Omitted: built-in default `table,json` — no collection-level default exists for
this field.

Not gated: this only controls what gets published, not what gets found or what the
gate evaluates.

Blank fails with `Input "formats" must contain at least one value, got "<raw>".`
An unrecognized entry fails with `Input "formats" has value "<part>". Allowed
values: table, json, sarif.`

### `generateSbom`

Optional pick list. `off` (default), `cyclonedx` or `spdx-json`. When not `off`,
runs one extra trivy invocation producing an SBOM in the chosen format, published
as the `TrivySBOM` build artifact.

Omitted: built-in default `off` — no collection-level default exists for this
field.

Not gated, for the same reason as `formats`.

### `publishArtifact`

Optional boolean. Whether to publish trivy's raw JSON report as the `TrivyReports`
build artifact (in addition to the normalized-report build attachment, which
always happens regardless of this setting).

Omitted: built-in default `true` — no collection-level default exists for this
field.

Not gated: publishing the raw report changes nothing about the scan or the gate.

### `publishTestResults`

Optional boolean. Converts the same parsed report the gate already evaluated into
a JUnit XML document and publishes it as a test run, giving every finding its own
row (with history) in the Tests tab. See the README's "Publishing findings to the
Tests tab" section and `examples/07-publish-test-results.yml` for the caveat that
every finding becomes a *failed* test case regardless of whether the gate itself
passed.

Omitted: built-in default `false` — no collection-level default exists for this
field.

Not gated: it adds a second, opt-in view onto results the gate has already
evaluated; it changes nothing about the scan, the gate, or which findings exist.

### `targetRegistryConnection`

Optional. The name of a Docker Registry service connection whose credentials
trivy uses to pull the scanned image (for `scanType: image`) from a private
registry. Reaches trivy as `TRIVY_USERNAME`/`TRIVY_PASSWORD` — the same two
environment variables the resolved database's own credentials would otherwise
use (the linked `databases` catalogue entry's `registryUsername`/
`registryPassword`, or, for a runner with no database linked, the deprecated
`dbRegistryUsername`/`dbRegistryPassword` on `defaults` — see "Where the
database comes from" above); if both are configured, this input's credentials
win for the scan and the database's credentials are dropped with a warning
(see the README).

Omitted: no registry credentials are supplied; the pull is attempted anonymously.

Not gated — not a member of `OverridableField`. It selects a credential, which is
a different concern from the severity/gate policy the Policy tab protects; the
source gives no further explicit rationale for exempting it.

### `configConnection`

Optional. The name of a Generic service connection whose token (a PAT with
extension-data scope) the task uses to read the collection's `runners`/
`defaults`/`databases` settings documents, instead of the build job's own OAuth
token (`System.AccessToken`). Only needed if that OAuth token is not authorized
to read extension data on this on-premises server.

Omitted: the job's own `System.AccessToken` is used.

Not gated — not even part of `TaskInputs`/`ResolvedScanConfig` at all; it governs
how the task authenticates to read its *own* configuration, before any scan-policy
question is reached.

### `useDockerSocket`

Optional boolean. Mounts `/var/run/docker.sock` into the scan container (in both
`mount` and `copy` source-transfer modes), giving trivy inside the container
access to the agent's own docker daemon — needed to scan an image that was just
built locally and never pushed anywhere (see
`examples/04-image-scan-local-daemon.yml`).

Omitted: falls back to the collection's built-in default `false`. There is no
collection-level default value for this field either — only allow/deny.

Gated: granting the scan container access to the host's docker daemon is a
privileged capability unrelated to the scan's own findings, so an administrator
may want to control which pipelines get it.

### `sourceTransfer`

Optional pick list. `mount` (default) bind-mounts the sources directory into the
scan container; `copy` streams them in with `docker cp` instead, for when the
docker daemon does not share a filesystem with the agent (see the README's
"Running the agent itself in a container" section and
`examples/03-kubernetes-agent-copy-source-transfer.yml`). Has no effect on an
`image` scan, which never mounts the sources directory either way.

Omitted: built-in default `mount` — no collection-level default exists for this
field.

Not gated: it describes the agent's own topology, not a security policy: there is
no gate-integrity reason to restrict it, and a collection can freely mix agent
pools with different topologies.

### `skipDbUpdate`

Optional boolean. Passes `--skip-db-update` to trivy, skipping the vulnerability
database refresh for this scan (relying on whatever is already in `cacheDir`).

Omitted: falls back to the collection's `defaults.skipDbUpdate`, or the built-in
default `false`.

Gated, for the same reason as `ignoreUnfixed` and `scanners` — it changes what
trivy can find.

### `timeoutMinutes`

Optional. A positive number of minutes trivy is allowed to run before the task
kills it and fails the build. Passed to the docker process as a wall-clock bound
(`timeoutMinutes * 60_000 + 30_000` ms) as well as to trivy's own `--timeout` flag.

Omitted: falls back to the collection's `defaults.timeoutMinutes`, or the built-in
default `10`.

Gated. A non-positive or non-numeric value fails with `Input "timeoutMinutes"
must be a positive number, got "<raw>".`

### `extraTrivyArgs`

Optional. Free-form additional trivy CLI arguments, parsed with shell-like
quoting but no shell semantics (see "Reserved trivy flags" above). Used, for
example, as a labelled stopgap for `--insecure` against a registry whose
certificate is not yet trusted (`examples/09-internal-ca-registry.yml`) — the
long-term fix belongs in the runner's "Extra docker args" instead.

Omitted: no extra arguments are passed.

Gated — the field most directly capable of working around every other lock, so
it is treated accordingly; see "Which inputs are policy-gated" above.

### `workingDirectory`

Optional. Directory to run the scan from, relative to the sources directory (not
absolute) — for example `services/api`. Passed as `-w` to the scan container.

Omitted: the scan runs from the mounted workspace root.

Not gated — not a member of `OverridableField`; the source gives no further
explicit rationale beyond its absence from that list.

A value that resolves outside the mounted sources directory is rejected the same
way `ignoreFile` is: `"workingDirectory" value "<value>" escapes the mounted
workspace (resolves to "<resolved>"). Use a path relative to the sources root.`
