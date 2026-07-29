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

This version has no administration UI: the runner catalog and the severity/gate defaults are
centrally managed settings, but you configure them by writing two JSON documents directly
through the Azure DevOps Extension Data REST API. An administration UI for this is planned for
a later release.

Both documents live in the extension's `%24settings` collection (`%24` is the URL-encoded `$`
that the Extension Data Service requires in the collection name). Set these once:

```bash
export ADO="https://ado.corp/DefaultCollection"
export PAT="<pat-with-extension-data-scope>"
export PUB="iksoftware"; export EXT="trivy-docker-scanner"
```

### `runners` — the runner catalog

```bash
curl -sS -u ":$PAT" -X PUT \
  "$ADO/_apis/ExtensionManagement/InstalledExtensions/$PUB/$EXT/Data/Scopes/Default/Current/Collections/%24settings/Documents?api-version=3.2-preview.1" \
  -H 'Content-Type: application/json' \
  -d '{"id":"runners","__etag":-1,"value":[{"alias":"baseline","image":"reg.corp/trivy:0.58.1","isDefault":true,"enabled":true}]}'
```

Validation rules (`src/shared/validation.ts`): `alias` must be lowercase letters, digits and
dashes, 2-31 characters; `image` needs an explicit tag other than `latest`, or a `@sha256:...`
digest; the catalog must contain exactly one runner with `isDefault: true` that is not disabled
(`enabled: false`).

### `defaults` — severity, gate and database defaults

```bash
curl -sS -u ":$PAT" -X PUT \
  "$ADO/_apis/ExtensionManagement/InstalledExtensions/$PUB/$EXT/Data/Scopes/Default/Current/Collections/%24settings/Documents?api-version=3.2-preview.1" \
  -H 'Content-Type: application/json' \
  -d '{"id":"defaults","__etag":-1,"value":{"dbRepository":"reg.corp/trivy-db:2"}}'
```

`dbRepository` (the OCI reference of the internal vulnerability-database mirror) is the only
required field, since build agents have no internet access. Everything else — `severities`,
`scanners`, `failOn`, `timeoutMinutes`, `allowOverrides`, ... — is optional and falls back to
the task's built-in defaults when omitted (see `src/shared/types.ts` for the full shape).

Read either document back to confirm it saved:

```bash
curl -sS -u ":$PAT" \
  "$ADO/_apis/ExtensionManagement/InstalledExtensions/$PUB/$EXT/Data/Scopes/Default/Current/Collections/%24settings/Documents/runners?api-version=3.2-preview.1"
```

### The `configConnection` input

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
