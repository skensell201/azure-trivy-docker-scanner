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
| `docs/superpowers` | Design spec, plans and spike results |

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
