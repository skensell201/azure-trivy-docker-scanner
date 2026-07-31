# Trivy Docker Scanner for Azure DevOps

Azure DevOps Server extension that runs Trivy from a docker runner image chosen from a
centrally managed catalog.

![icon](images/icon.svg)

## Requirements

- Azure DevOps Server 2022 or newer
- Linux build agents with docker available to the agent user
- An internal OCI registry mirror of the Trivy database

Windows agents are not supported in v1.

## Repository layout

| Path | Contents |
|---|---|
| `src/shared` | Types and validation shared by the task and the UI |
| `src/task` | Pipeline task `TrivyScan@1` |
| `test/fixtures` | Real trivy output used by the parser tests |
| `test/integration` | Scan run against a fake docker binary |
| `examples` | Complete, runnable pipelines for common scenarios |
| `docs/inputs.md` | Reference for every task input: types, defaults, precedence, policy gating |
| `docs/superpowers` | Design spec and implementation plans |

## Examples

The [`examples`](examples) directory has one complete pipeline per scenario — a plain
Linux agent, a Kubernetes agent reaching docker through a mounted socket
(`sourceTransfer: copy`), scanning a locally built image vs. one in a private
registry, IaC scanning, publishing to the Tests tab, SARIF/SBOM artifacts, the
internal-CA registry stopgap, and two runners each backed by its own vulnerability
database. Each file starts with a comment explaining what it assumes and what it
produces; copy one wholesale as a starting point.

## Task inputs

Every input `TrivyScan@1` accepts — its type, accepted values, what happens when
it is omitted, and whether the collection's Policy tab can lock it — is documented
in [`docs/inputs.md`](docs/inputs.md), including the precedence between built-in
defaults, the collection's Defaults tab, and pipeline inputs.

## Configuration

Administration is collection-wide, not per-project: there is one runner catalog, one vulnerability
database catalogue, and one set of severity/gate defaults for the whole Azure DevOps collection,
and every project's pipelines consume the same catalog, catalogue and defaults. There is no
per-project configuration. A database is a property of the runner that uses it rather than a
single collection-wide value, since a runner backed by a custom trivy image may ship with, and
expect, its own database — but the catalogue it is chosen from is still collection-wide.

### Admin hub (Collection Settings > Trivy Scanner)

The primary way to configure the collection-wide settings is the **Trivy Scanner** hub: open
**Collection Settings** (the gear icon, top right of any project) and pick **Trivy Scanner** from
the left-hand navigation. The hub has four tabs, each backed by the same validation rules the
task itself applies (`src/shared/validation.ts`), so a setting that would fail in the pipeline is
rejected in the form instead:

- **Runners** — the runner catalog: add, edit, enable/disable and delete entries. Each runner has
  an `alias`, an `image` (with an explicit tag or a digest, never `latest`), optional
  `displayName`/`description`/`extraDockerArgs`, an `isDefault` flag (exactly one enabled runner
  must be default), an `enabled` flag, an optional `registryUsername`/`registryPassword` pair
  for pulling the image from a private registry, and a `database` — the alias of one entry from
  the Databases tab below, chosen from a select rather than typed. A runner with no database
  linked falls back to the deprecated fields on the Defaults tab (see below).
- **Databases** — the vulnerability-database catalogue (the `databases` document): one or more
  named entries, each with an `alias`, a `repository`, an optional `javaRepository`, an optional
  `registryUsername`/`registryPassword` pair, and optional `displayName`/`description`. A database
  is a property of the runner that uses it rather than a single collection-wide setting, because a
  runner backed by a custom trivy image may ship with, and expect, its own vulnerability database
  instead of the official one. Deleting a database that a runner still points at is refused, and
  the error names the runner.
- **Defaults** — the `defaults` document: `severities`, `scanners`, `failOn`, `timeoutMinutes`,
  `ignoreUnfixed`, `skipDbUpdate`, `cacheDir`. It also still *stores* the pre-catalogue database
  fields (`dbRepository`, `javaDbRepository`, `dbRegistryUsername`, `dbRegistryPassword`) for any
  runner that has not been linked to a catalogue entry yet, but the form no longer shows them —
  they are carried through unchanged on every save of this tab, precisely so that saving an
  unrelated default (say, a new `timeoutMinutes`) can never wipe out the fallback a not-yet-migrated
  runner's scans currently depend on. See "Migrating to the database catalogue" below.
- **Policy** — `allowOverrides`: a checkbox per overridable pipeline input
  (`src/shared/types.ts`'s `OverridableField`). Leaving a box unchecked means a pipeline's own
  input for that field is rejected and the collection's default is enforced instead.

The runner and database password fields never display a saved value: once a password is
set, the field shows "a password is stored" and a **Replace password** button instead of the
value itself, so opening the form cannot leak the credential and saving it back without touching
that field cannot blank it out. The form also repeats, next to the field, the same warning given
below: **the password is stored in clear text** in the extension settings document and is
readable by anyone with extension-data read access to this collection — this applies equally to
the runner catalog's credentials and to every catalogued database's credentials.

Saves are read-modify-write against the document's `__etag`: if another administrator saved
between your load and your save, the hub tells you someone else changed the settings instead of
silently overwriting their edit — reload the page to see the current version, then reapply your
change.

#### Approving the raised permission on upgrade

Starting with `0.2.0` the extension requests `vso.extension.data_write` (previously
`vso.extension.data`, read-only), because the hub now writes the settings documents that used to
be written by hand. Raising a scope is not silent: Azure DevOps requires a collection
administrator to **approve the updated permissions** before the new version takes effect. If
`0.2.0` is installed without that approval, the hub fails to load and says so explicitly (an
error naming the failure, not an endless spinner) instead of pretending to work. To approve it,
go to **Organization/Collection Settings > Extensions**, find **Trivy Docker Scanner**, and accept
the permission prompt shown there (Azure DevOps Server surfaces this as a banner or an "Update"
action on the extension's row); then reload the hub page.

#### Migrating to the database catalogue (0.5.0)

Before `0.5.0`, the vulnerability database was one collection-wide setting on the Defaults tab
(`dbRepository`/`javaDbRepository`/`dbRegistryUsername`/`dbRegistryPassword`). Starting with
`0.5.0` it is a catalogue, on its own **Databases** tab, because a database belongs to the runner
that uses it, not to the collection: a runner backed by a custom trivy image may ship with, and
expect, its own database rather than the official one.

**Nothing breaks on upgrade, and nothing needs to happen immediately.** The four fields on the
Defaults tab still exist in the `defaults` document and are still honoured — a runner with no
`database` linked keeps using them exactly as before. The Defaults form itself no longer shows
these fields, but saving it (for any unrelated change, such as a new `timeoutMinutes`) carries
their stored values through untouched, so routine administration cannot silently erase the
fallback current scans depend on.

To migrate a collection:

1. Open **Collection Settings > Trivy Scanner > Databases** and add an entry — an `alias`, the
   database `repository` (and, if you scan Java artifacts, `javaRepository`), and credentials if
   the mirror needs them. This is the same value that used to live in `dbRepository` on the
   Defaults tab.
2. Open **Collection Settings > Trivy Scanner > Runners**, edit each runner, and pick that entry
   from the new **Database** select (it replaces free-text typing with a choice from the
   catalogue you just created).
3. Once every runner names a database, the deprecated Defaults fields are no longer read by
   anything and can be left blank or cleared.

**What the build-log warning means.** Until a runner is migrated, every scan that runner performs
logs a warning of the shape:

```
Runner "baseline" has no database linked, so this scan used the collection's deprecated
dbRepository/javaDbRepository (and dbRegistryUsername/dbRegistryPassword, if set) defaults
instead. Link a database to this runner in the admin hub (Collection Settings > Trivy Scanner >
Runners) before those deprecated fields are removed.
```

This is not an error — the scan still ran, using the deprecated fallback — it is a per-run,
per-runner reminder naming exactly which runner in step 2 above still needs a database linked.
Once every runner names one, the warning stops appearing.

### Configuring via the REST API (alternative, for scripting)

The hub covers everything an administrator needs interactively. The same three settings documents
can still be read and written directly through the Azure DevOps Extension Data REST API — this
keeps working after `0.2.0` and remains useful for scripted or bulk changes, but it is no longer
the primary path.

Both documents live in the extension's `%24settings` collection (`%24` is the URL-encoded `$`
that the Extension Data Service requires in the collection name). Set these once:

```bash
export ADO="https://dev.example.com/DefaultCollection"
export PAT="<pat-with-extension-data-scope>"
export PUB="iksoftware"; export EXT="trivy-docker-scanner"
```

#### `runners` — the runner catalog

```bash
curl -sS -u ":$PAT" -X PUT \
  "$ADO/_apis/ExtensionManagement/InstalledExtensions/$PUB/$EXT/Data/Scopes/Default/Current/Collections/%24settings/Documents?api-version=3.2-preview.1" \
  -H 'Content-Type: application/json' \
  -d '{"id":"runners","__etag":-1,"value":[{"alias":"baseline","image":"registry.example.com/trivy:0.58.1","isDefault":true,"enabled":true,"database":"internal-mirror","registryUsername":"svc-trivy","registryPassword":"<password>"}]}'
```

`database` names an entry from the `databases` catalogue below by `alias` (here, `internal-mirror`)
— this is how a runner picks which vulnerability database it uses. It is optional only for
compatibility with a settings document written before the catalogue existed: a runner with no
`database` set falls back to the deprecated `dbRepository`/`javaDbRepository`/
`dbRegistryUsername`/`dbRegistryPassword` fields on the `defaults` document instead (see
"Migrating to the database catalogue" above), and every scan that runner performs logs a warning
saying so. A new runner should always set `database` explicitly.

Validation rules (`src/shared/validation.ts`): `alias` must be lowercase letters, digits,
dashes, underscores and dots, 2-31 characters, starting with a letter or digit; `image` needs
an explicit tag other than `latest`, or a `@sha256:...`
digest; the catalog must contain exactly one runner with `isDefault: true` that is not disabled
(`enabled: false`); `registryUsername` and `registryPassword` are optional but must be set
together — one without the other fails validation; `database`, if set, must name an alias that
actually exists in the `databases` catalogue.

If a runner carries `registryUsername`/`registryPassword`, the task runs
`docker login <host> --username <user> --password-stdin` for the registry that hosts its image
before pulling it, so a private corporate registry works even though this task is otherwise
air-gapped. **The password is stored in plain text in this settings document** — the Azure
DevOps Extension Data Service is not a secret store — and is readable by anyone who has
extension-data read access to this collection (the same access that lets someone read the document
back with the `curl` command above). Grant that access accordingly, and prefer a scoped
service/robot account over a personal one for `registryUsername`.

These fields are only needed when the registry actually requires authentication; if it
allows anonymous pulls, leave both empty. A failed login no longer aborts the scan — it
is logged as a warning and the task proceeds to pull the image and scan anyway, since
some registries reject `docker login` for reasons unrelated to whether an anonymous pull
will succeed.

#### `databases` — the vulnerability-database catalogue

```bash
curl -sS -u ":$PAT" -X PUT \
  "$ADO/_apis/ExtensionManagement/InstalledExtensions/$PUB/$EXT/Data/Scopes/Default/Current/Collections/%24settings/Documents?api-version=3.2-preview.1" \
  -H 'Content-Type: application/json' \
  -d '{"id":"databases","__etag":-1,"value":[{"alias":"internal-mirror","repository":"registry.example.com/trivy-db:2","javaRepository":"registry.example.com/trivy-java-db:1","registryUsername":"svc-trivy-db","registryPassword":"<password>"}]}'
```

This document is a list of database entries, the same shape as `runners` above, each one a named,
reusable vulnerability database that one or more runners can point at by `alias`
(`runners[].database`, see above). A database is a property of the runner that uses it, not a
collection-wide setting — a runner backed by a custom trivy image may ship with, and expect, its
own database rather than the official one. There is no "default database": a runner either names
one explicitly, or falls back to the deprecated fields on `defaults` (see the next section and
"Migrating to the database catalogue" above).

Validation rules (`src/shared/validation.ts`): `alias` follows the same shape rule as a runner
alias; `repository` needs an explicit tag other than `latest`, or a `@sha256:...` digest, same as
a runner's `image`; `javaRepository`, if set, is held to the same rule; `registryUsername` and
`registryPassword` are optional but must be set together, same as the runner catalog's pair.
Deleting an entry that a runner still points at is refused — the error names the runner, so an
administrator can re-link or remove it there first.

Trivy pulls its database from *inside* the container, so a database entry's credentials reach it
through `TRIVY_USERNAME`/`TRIVY_PASSWORD` in the container's environment — the same two variables
the task already uses for the scanned image's own registry credentials
(`targetRegistryConnection`, a per-pipeline task input). Trivy has no second pair of variables,
and this task does not attempt per-registry credential mapping. If a pipeline sets
`targetRegistryConnection` credentials, they win and the database's credentials are ignored for
that run, with a warning explaining why; otherwise the database's own credentials are used. **The
password is stored in plain text in this settings document**, same caveat as the runner catalog's
`registryPassword` above.

#### `defaults` — severity and gate defaults (plus a deprecated database fallback)

```bash
curl -sS -u ":$PAT" -X PUT \
  "$ADO/_apis/ExtensionManagement/InstalledExtensions/$PUB/$EXT/Data/Scopes/Default/Current/Collections/%24settings/Documents?api-version=3.2-preview.1" \
  -H 'Content-Type: application/json' \
  -d '{"id":"defaults","__etag":-1,"value":{"severities":["HIGH","CRITICAL"],"failOn":"CRITICAL"}}'
```

Every field is optional and falls back to the task's built-in defaults when omitted:
`severities`, `scanners`, `failOn`, `timeoutMinutes`, `ignoreUnfixed`, `skipDbUpdate`, `cacheDir`,
`allowOverrides` (see `src/shared/types.ts` for the full shape). A fully migrated configuration
has no database settings in this document at all — that belongs in the `databases` catalogue
above, linked to a runner by alias.

This document also still carries four **deprecated** fields from before the catalogue existed:
`dbRepository`, `javaDbRepository`, `dbRegistryUsername`, `dbRegistryPassword`. They are honoured
as the fallback for any runner with no `database` linked (and every scan that falls back logs a
warning naming that runner — see "Migrating to the database catalogue" above), but a new
configuration should not set them; use the `databases` document instead. `dbRegistryUsername` and
`dbRegistryPassword` are optional but must be set together, same as every other credential pair
here, and carry the **same plain-text-storage caveat**. If you are writing this document by hand
for a collection that predates `0.5.0`, these four fields still work exactly as before.

Read any of the three documents back to confirm it saved:

```bash
curl -sS -u ":$PAT" \
  "$ADO/_apis/ExtensionManagement/InstalledExtensions/$PUB/$EXT/Data/Scopes/Default/Current/Collections/%24settings/Documents/runners?api-version=3.2-preview.1"
```

### Internal certificate authorities (on-premises servers)

On a server whose HTTPS certificate is issued by an internal CA, the task can fail on its very
first request — reading the `runners` settings document — with an error like:

```
Could not reach https://azure.example.com/Datagile to read the "runners" settings document:
unable to get local issuer certificate
```

This is not a network or permissions problem: the build agent itself is .NET and reads the
operating system's trust store without trouble, but this task is Node, and Node on Linux does
**not** read the OS trust store — it carries its own bundled root certificates. Every collection
whose Azure DevOps Server sits behind an internal PKI hits this immediately, and the symptom does
not obviously point at certificates.

Starting with `0.2.1` the task handles this automatically, and `0.2.2` closes the gap that
mattered most in practice — an agent that was never given `--sslcacert` at all:

- **The agent's own `--sslcacert` configuration is honored first.** If the agent was installed
  with a CA file (`tl.getHttpCertConfiguration().caFile`, the same setting the agent itself uses),
  the task reads it and trusts it for its own HTTPS calls, in addition to Node's bundled roots. No
  configuration is needed on the task or the pipeline for this case — if the agent already trusts
  the server, so does the task. If that CA file cannot be read for some reason, the task logs a
  warning naming the path and continues with Node's default trusted roots, since the request may
  still succeed anyway (for example, behind a load balancer with a public certificate).
- **The operating system's own trust bundle is used automatically on Linux agents** when the
  agent has no `--sslcacert` configured. This is the common on-premises case: the OS already trusts
  the internal CA (docker pulls from the internal registry already prove that), but Node on Linux
  never consults the OS trust store on its own — it carries its own bundled roots instead. The task
  now looks for the OS bundle at the usual locations (`/etc/ssl/certs/ca-certificates.crt`,
  `/etc/pki/tls/certs/ca-bundle.crt`, `/etc/ssl/ca-bundle.pem`) and trusts whichever one it finds,
  again in addition to Node's bundled roots. **No pipeline change is needed for this case either.**
  Windows and macOS agents have none of these paths and simply fall through to Node's defaults, as
  before.
- **`NODE_EXTRA_CA_CERTS` remains a fallback** for the unusual layout neither of the above covers
  (a CA bundle somewhere other than the well-known paths, or a non-Linux agent). Set it as an
  environment variable on the pipeline step, pointing at a PEM file on the agent, and Node picks it
  up directly:

  ```yaml
  - task: TrivyScan@1
    env:
      NODE_EXTRA_CA_CERTS: /etc/ssl/certs/internal-ca.pem
    inputs:
      target: myregistry.example.com/app:1.0
  ```

- **Trivy itself has the same problem, separately, inside the container.** The task's own HTTPS
  calls (reading settings, described above) run in Node on the agent host; Trivy's calls (pulling
  its vulnerability database and pulling/inspecting the scanned image) run as its own process
  inside the runner container and make their own TLS connections to the registry — they do not
  inherit the agent's or the task's trust configuration at all. If Trivy's registry is also behind
  the internal CA, mount the CA certificate into the container's trust store via the runner's
  **Extra docker args** field in the admin hub (Collection Settings > Trivy Scanner > Runners),
  for example:

  ```
  -v /etc/ssl/certs/internal-ca.pem:/etc/ssl/certs/internal-ca.pem:ro
  ```

  (Adjust the container path to wherever the runner image's trust store expects extra CA files.)

`--insecure` in `extraTrivyArgs` works as a stopgap that lets a scan proceed against an untrusted
certificate, but it disables certificate verification entirely for that request — it should not be
left in a pipeline long-term; fix the trust configuration above instead once it is confirmed
working.

#### The `configConnection` input

By default the task reads both documents using the build job's own OAuth token
(`System.AccessToken`). Whether that token is authorized to read extension data is unverified
on an on-premises Azure DevOps Server — it depends on server version and job authorization
settings. If reads fail with an authorization error, set the task's `configConnection` input to
a "Generic" service connection whose token is the PAT described above; the task then reads the
settings documents with that PAT instead of the job's OAuth token.

### Running the agent itself in a container

This task assumes a conventional build agent: a process on a VM or bare host, talking to a
docker daemon that shares its view of the filesystem. That assumption breaks down when the agent
itself runs in a container — for example a Kubernetes pod — with the docker daemon reached
through a sidecar or a mounted host socket. In that setup the daemon and the agent can be in
different mount namespaces, and the requirement is not optional: **the docker daemon must see the
agent's sources directory at the same absolute path the agent uses**, because that is what a bind
mount (`-v <sourcesDir>:/workspace`) means — the daemon resolves that path itself, not this task,
so it has no way to translate it.

When the daemon cannot see that path, it does not fail the mount outright — it silently
substitutes an empty directory. The scan then fails with something like:

```
INFO  Number of language-specific files  num=0
FATAL run error: report error: unable to write results: failed to create a file:
      failed to create output file: open /workspace/.trivy/report-0.json: no such file or directory
```

Starting with this version, the task recognizes this specific shape — trivy could not create its
report at the container path, and the report file never appeared on the host — and names the real
cause instead of a generic "docker exited with code 1" message.

One step settles whether this is what is happening, before or independent of trying a real scan:

```yaml
- bash: |
    ls -la "$(Build.SourcesDirectory)" | head -5
    docker run --rm -v "$(Build.SourcesDirectory)":/workspace alpine ls -la /workspace | head -5
```

If the first listing shows the checked-out repository and the second is empty, the daemon cannot
see that path — confirmed independently of trivy or this task.

The usual fixes, depending on how the daemon is reached:

- **Sidecar daemon** (a separate container in the same pod): mount the same volume at the same
  `mountPath` in both the agent container and the daemon container, so both see it at the same
  absolute path.
- **Host's daemon via a mounted socket** (`/var/run/docker.sock`): mount the same host path into
  the agent container at that same location, so the path the agent passes to `-v` is one the host
  daemon already recognizes.

This task does not attempt to *guess* its way around the mismatch (no path translation, no
auto-detection of the agent's topology) — guessing at a host-to-daemon path mapping could produce a
scan that silently runs against the wrong (or empty) directory, which is worse than failing
loudly. But it does offer an explicit, opt-in remedy that needs no path mapping at all: see
`sourceTransfer: copy` below.

Note this only affects **filesystem**, **repository**, and **config** scans, which all depend on
mounting the sources directory into the container. An **image** scan pulls the image by
reference and never mounts `sourcesDir`, so it is unaffected by this class of failure — and
`sourceTransfer` has no effect on an image scan either, for the same reason.

#### `sourceTransfer: copy` — when there is no shared filesystem to fix

Set the task's `sourceTransfer` input to `copy` when you cannot fix the mismatch above — for
example, a shared agent pool you do not administer, or a cluster where the daemon and the agent
will never share a filesystem by design. `copy` mode never bind-mounts the sources at all: instead
it `docker create`s the container, places the sources with `docker cp` (which streams a tar over
the docker API to the daemon, the same way a `docker save`/`docker load` pipe would, rather than
asking the daemon to resolve a host path), `docker start -a`s it to run the scan, then `docker cp`s
the report back out and removes the container. None of that requires the daemon to see anything on
the agent's own filesystem, so it works identically whether the daemon is local, a sidecar, or the
host's daemon reached through a mounted socket.

```yaml
- task: TrivyScan@1
  inputs:
    scanType: filesystem
    target: .
    sourceTransfer: copy
```

Two costs come with it, and they apply on every scan, not just the first one after switching:

- **The sources are streamed into the container on every scan.** For a large repository this is
  slower than a bind mount, which costs nothing to set up per run.
- **The vulnerability database cannot use this agent's local cache.** The cache directory
  (`cacheDir`) is itself a bind mount, resolved by the same daemon that cannot see this agent's
  filesystem in the first place — mounting it in `copy` mode would just silently hand trivy an
  empty cache, the same failure shape this whole feature exists to avoid, only relocated. So in
  `copy` mode the cache mount is dropped instead, and trivy downloads the vulnerability database
  fresh on every scan.

`sourceTransfer` defaults to `mount` (today's behavior, unchanged) and is never inferred — leave it
alone unless you have confirmed, the way the `bash` snippet above does, that the daemon genuinely
cannot see this agent's sources directory.

## Publishing findings to the Tests tab

By default, findings are readable in the build log's table (`formats: table`), a build issue per
blocking finding, the JSON report attached to the build, and the `TrivyReports` artifact — but
none of those give a single finding its own history across runs. Azure DevOps's **Tests** tab
already does exactly that for free: a row per test, "Failing since" dates, New vs. Existing
tracking, and filtering, with no custom UI to build or maintain. Set `publishTestResults: true`
to get it:

```yaml
- task: TrivyScan@1
  inputs:
    target: app:1.4.2
    publishTestResults: true
```

That one line converts the same normalized report the gate already evaluated into a JUnit XML
document (`src/task/JUnitReport.ts`) and publishes it with the `results.publish` logging command.
Every finding becomes its own `<testcase>`, named `[SEVERITY] ID` (e.g. `[CRITICAL]
CVE-2024-21626`) so it stays the same test across runs and the tab's per-test history actually
means something, grouped by finding kind (vulnerability/secret/misconfiguration/license) via
`classname` so the tab can filter by it. The failure message carries the affected package,
installed and fixed versions, and the title; the longer detail (target, location, full title)
sits in the failure body. A clean scan still publishes one run, with a single synthetic passing
test case rather than an empty (and easily mistaken for broken) test run.

The **Run duration** shown for that run in the Tests tab is the trivy scan's own duration (the
time the docker invocation actually took), not a per-test or per-finding time — JUnit has no
meaningful notion of the latter for a report converted from a single already-parsed scan, so
every `<testcase>` carries `time="0"` and only the `<testsuite>` carries the real number.

**Every finding becomes a *failed* test case — this is the point, not a bug.** A pipeline whose
gate passes (the findings are all below `failOn`, or the gate is disabled with `failOn: none`)
will still show red in the Tests tab once this is on: the gate and the Tests tab answer different
questions ("should the build fail" vs. "what needs attention, with history"), and a build can
legitimately be green while its tests are red. That surprising-by-default combination is exactly
why `publishTestResults` defaults to `false` — turning it on is a deliberate choice for a team
that wants this view, not something every pipeline should wake up to.

The JSON report attachment and the `TrivyReports` build artifact are unaffected either way: this
is a third, independent publishing mechanism layered on top of the same parsed report, not a
replacement for either of the other two.

## Troubleshooting

- **An empty scan is a normal outcome.** When trivy finds nothing at all — no vulnerable
  packages, no secrets, no failing misconfigurations — it reports zero findings rather than
  failing. Depending on the trivy version, that report may omit the `Results` key entirely
  instead of emitting `"Results": []`; both shapes are recognized and reported as no findings,
  not as an error.

## Development

```bash
npm install
npm test
npm run lint
npm run typecheck
npm run package    # produces out/*.vsix
```

## License

MIT
