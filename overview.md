# Trivy Docker Scanner

Runs [Trivy](https://github.com/aquasecurity/trivy) inside a docker container from a curated
catalog of runner images, so every pipeline in the collection scans with the image the security
team approved.

## Why this instead of running trivy directly

- **Curated runners.** Administrators register the allowed trivy images in Project Settings.
  Pipelines pick one by alias, so upgrading trivy everywhere is a single edit.
- **Works in a closed network.** The vulnerability database comes from an internal OCI registry
  mirror and a persistent cache on the agent. No call ever leaves your network.
- **One place for the gate.** Severity thresholds live in project settings; pipelines may
  override only what the policy allows.
- **Readable results.** A Trivy tab on the build shows why the gate failed, the counts per
  severity, and every finding with filters.

## Quick start

```yaml
- task: TrivyScan@1
  inputs:
    scanType: image
    target: myapp:$(Build.BuildId)
```

Configure runners and defaults under **Project Settings > Trivy Scanner**.
