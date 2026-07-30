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
| `docs/superpowers` | Design spec and implementation plans |

## Configuration

Administration is collection-wide, not per-project: there is one runner catalog and one set of
severity/gate defaults for the whole Azure DevOps collection, and every project's pipelines
consume the same catalog and defaults. There is no per-project configuration.

### Admin hub (Collection Settings > Trivy Scanner)

The primary way to configure the collection-wide settings is the **Trivy Scanner** hub: open
**Collection Settings** (the gear icon, top right of any project) and pick **Trivy Scanner** from
the left-hand navigation. The hub has three tabs, each backed by the same validation rules the
task itself applies (`src/shared/validation.ts`), so a setting that would fail in the pipeline is
rejected in the form instead:

- **Runners** — the runner catalog: add, edit, enable/disable and delete entries. Each runner has
  an `alias`, an `image` (with an explicit tag or a digest, never `latest`), optional
  `displayName`/`description`/`extraDockerArgs`, an `isDefault` flag (exactly one enabled runner
  must be default), an `enabled` flag, and an optional `registryUsername`/`registryPassword` pair
  for pulling the image from a private registry.
- **Defaults** — the `defaults` document: `dbRepository` (the only required field, since agents
  have no internet access), plus `severities`, `scanners`, `failOn`, `timeoutMinutes`,
  `ignoreUnfixed`, `skipDbUpdate`, `javaDbRepository`, `cacheDir`, and
  `dbRegistryUsername`/`dbRegistryPassword` for the database-mirror registry.
- **Policy** — `allowOverrides`: a checkbox per overridable pipeline input
  (`src/shared/types.ts`'s `OverridableField`). Leaving a box unchecked means a pipeline's own
  input for that field is rejected and the collection's default is enforced instead.

The runner and database-mirror password fields never display a saved value: once a password is
set, the field shows "a password is stored" and a **Replace password** button instead of the
value itself, so opening the form cannot leak the credential and saving it back without touching
that field cannot blank it out. The form also repeats, next to the field, the same warning given
below: **the password is stored in clear text** in the extension settings document and is
readable by anyone with extension-data read access to this collection.

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

### Configuring via the REST API (alternative, for scripting)

The hub covers everything an administrator needs interactively. The same two settings documents
can still be read and written directly through the Azure DevOps Extension Data REST API — this
keeps working after `0.2.0` and remains useful for scripted or bulk changes, but it is no longer
the primary path.

Both documents live in the extension's `%24settings` collection (`%24` is the URL-encoded `$`
that the Extension Data Service requires in the collection name). Set these once:

```bash
export ADO="https://ado.corp/DefaultCollection"
export PAT="<pat-with-extension-data-scope>"
export PUB="iksoftware"; export EXT="trivy-docker-scanner"
```

#### `runners` — the runner catalog

```bash
curl -sS -u ":$PAT" -X PUT \
  "$ADO/_apis/ExtensionManagement/InstalledExtensions/$PUB/$EXT/Data/Scopes/Default/Current/Collections/%24settings/Documents?api-version=3.2-preview.1" \
  -H 'Content-Type: application/json' \
  -d '{"id":"runners","__etag":-1,"value":[{"alias":"baseline","image":"reg.corp/trivy:0.58.1","isDefault":true,"enabled":true,"registryUsername":"svc-trivy","registryPassword":"<password>"}]}'
```

Validation rules (`src/shared/validation.ts`): `alias` must be lowercase letters, digits and
dashes, 2-31 characters; `image` needs an explicit tag other than `latest`, or a `@sha256:...`
digest; the catalog must contain exactly one runner with `isDefault: true` that is not disabled
(`enabled: false`); `registryUsername` and `registryPassword` are optional but must be set
together — one without the other fails validation.

If a runner carries `registryUsername`/`registryPassword`, the task runs
`docker login <host> --username <user> --password-stdin` for the registry that hosts its image
before pulling it, so a private corporate registry works even though this task is otherwise
air-gapped. **The password is stored in plain text in this settings document** — the Azure
DevOps Extension Data Service is not a secret store — and is readable by anyone who has
extension-data read access to this collection (the same access that lets someone read the document
back with the `curl` command above). Grant that access accordingly, and prefer a scoped
service/robot account over a personal one for `registryUsername`.

#### `defaults` — severity, gate and database defaults

```bash
curl -sS -u ":$PAT" -X PUT \
  "$ADO/_apis/ExtensionManagement/InstalledExtensions/$PUB/$EXT/Data/Scopes/Default/Current/Collections/%24settings/Documents?api-version=3.2-preview.1" \
  -H 'Content-Type: application/json' \
  -d '{"id":"defaults","__etag":-1,"value":{"dbRepository":"reg.corp/trivy-db:2","dbRegistryUsername":"svc-trivy-db","dbRegistryPassword":"<password>"}}'
```

`dbRepository` (the OCI reference of the internal vulnerability-database mirror) is the only
required field, since build agents have no internet access. Everything else — `severities`,
`scanners`, `failOn`, `timeoutMinutes`, `allowOverrides`, `dbRegistryUsername`,
`dbRegistryPassword`, ... — is optional and falls back to the task's built-in defaults when
omitted (see `src/shared/types.ts` for the full shape). `dbRegistryUsername` and
`dbRegistryPassword` are optional but must be set together, same as the runner catalog's
credential pair above, and carry the **same plain-text-storage caveat**: anyone with
extension-data read access to this collection can read this password back.

Trivy pulls its database from *inside* the container, so these credentials reach it through
`TRIVY_USERNAME`/`TRIVY_PASSWORD` in the container's environment — the same two variables the
task already uses for the scanned image's own registry credentials
(`targetRegistryConnection`, a per-pipeline task input). Trivy has no second pair of variables,
and this task does not attempt per-registry credential mapping. If a pipeline sets
`targetRegistryConnection` credentials, they win and `dbRegistryUsername`/`dbRegistryPassword`
are ignored for that run, with a warning explaining why; otherwise the database-mirror
credentials are used.

Read either document back to confirm it saved:

```bash
curl -sS -u ":$PAT" \
  "$ADO/_apis/ExtensionManagement/InstalledExtensions/$PUB/$EXT/Data/Scopes/Default/Current/Collections/%24settings/Documents/runners?api-version=3.2-preview.1"
```

#### The `configConnection` input

By default the task reads both documents using the build job's own OAuth token
(`System.AccessToken`). Whether that token is authorized to read extension data is unverified
on an on-premises Azure DevOps Server — it depends on server version and job authorization
settings. If reads fail with an authorization error, set the task's `configConnection` input to
a "Generic" service connection whose token is the PAT described above; the task then reads the
settings documents with that PAT instead of the job's OAuth token.

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
