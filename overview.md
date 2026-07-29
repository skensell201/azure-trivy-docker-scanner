# Trivy Docker Scanner

Runs [Trivy](https://github.com/aquasecurity/trivy) inside a docker container from a curated
catalog of runner images, so every pipeline in the collection scans with the image the security
team approved.

## What this version ships

A pipeline task (`TrivyScan@1`) that runs Trivy from a chosen runner image, gates the build on
the findings, attaches the JSON report to the build, and can publish the report (and a
CycloneDX/SPDX SBOM) as a build artifact. There is no administration UI or build-results tab in
this version — both are planned for a later release.

## Why this instead of running trivy directly

- **Curated runners.** A centrally maintained catalog of approved trivy images; pipelines pick
  one by alias, so upgrading trivy everywhere is a single edit.
- **Works in a closed network.** The vulnerability database comes from an internal OCI registry
  mirror and a persistent cache on the agent. No call ever leaves your network.
- **One place for the gate.** Severity thresholds live in centrally managed settings; pipelines
  may override only what the policy allows.
- **Traceable results.** Findings are logged to the build summary (most severe first), the full
  JSON report is attached to the build, and the report or SBOM can be published as a build
  artifact for later inspection.

## Quick start

```yaml
- task: TrivyScan@1
  inputs:
    scanType: image
    target: myapp:$(Build.BuildId)
```

Centrally-managed settings (the runner catalog and severity/gate defaults) are configured
through the Azure DevOps Extension Data REST API in this version — see the project README for
the exact commands. An administration UI for this is planned.
