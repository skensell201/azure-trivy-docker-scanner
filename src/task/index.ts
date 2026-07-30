import * as fs from 'fs';
import * as tl from 'azure-pipelines-task-lib/task';
import { ConfigClient, FetchLike } from './ConfigClient';
import { createHttpFetch, httpFetch } from './httpFetch';
import { readInputs } from './inputs';
import { ChildProcessRunner } from './ProcessRunner';
import { Publisher } from './Publisher';
import { runScan } from './run';
import { validateCatalog, validateDefaults, validateRunner } from '../shared/validation';
import { AgentContext, DefaultsConfig, RunnerConfig } from '../shared/types';

const PUBLISHER = 'iksoftware';
const EXTENSION_ID = 'trivy-docker-scanner';

function agentContext(): AgentContext {
  return {
    sourcesDir: tl.getVariable('Build.SourcesDirectory') ?? process.cwd(),
    agentHomeDir: tl.getVariable('Agent.HomeDirectory') ?? process.cwd(),
    tempDir: tl.getVariable('Agent.TempDirectory') ?? process.cwd(),
    buildId: tl.getVariable('Build.BuildId') ?? '0',
  };
}

/**
 * Each task instance in a job gets its own index so reports and containers never collide.
 * `task.setvariable` publishes the incremented value as an environment variable for every
 * later step in the same job (not the current one, and not other jobs) - which is exactly
 * the scope a second `TrivyScan` step in the same job needs to see it.
 */
function nextScanIndex(): number {
  const raw = Number(process.env.TRIVY_SCAN_INDEX ?? '0');
  const index = Number.isFinite(raw) ? raw : 0;
  tl.setVariable('TRIVY_SCAN_INDEX', String(index + 1));
  return index;
}

/**
 * Reads the CA the agent was configured with at install time (`--sslcacert`, surfaced by
 * `tl.getHttpCertConfiguration().caFile`), so this task's own HTTPS calls trust the same internal
 * PKI the .NET agent already trusts via the OS trust store. Node on Linux does not read that
 * store - it carries its own bundled roots - so on a server with an internal CA this is the one
 * thing standing between a working task and "unable to get local issuer certificate" on literally
 * the first request the task makes (reading the "runners" settings document).
 *
 * `certFile`/`keyFile` (a client certificate, i.e. mutual TLS) are deliberately ignored: that is a
 * different feature from trusting a CA, nobody has asked for it, and wiring it through only
 * partway (e.g. without also handling `passphrase`/`certArchiveFile` correctly) would be worse
 * than not touching it at all.
 *
 * A CA file that cannot be read must not fail the whole task: the request may well succeed anyway
 * (a proxy or load balancer terminating TLS with a publicly-trusted cert, for instance), so this
 * warns, names the path, and falls back to `httpFetch` (Node's bundled roots only) rather than
 * throwing.
 */
function buildFetch(): FetchLike {
  const certConfiguration = tl.getHttpCertConfiguration();
  if (!certConfiguration?.caFile) {
    return httpFetch;
  }

  try {
    const ca = fs.readFileSync(certConfiguration.caFile);
    return createHttpFetch({ ca });
  } catch (error) {
    tl.warning(
      `The agent's configured CA file (${certConfiguration.caFile}) could not be read: ` +
        `${(error as Error).message}. Continuing with Node's default trusted roots; the request ` +
        'may still succeed.',
    );
    return httpFetch;
  }
}

/**
 * The authorization mode a build agent can use to read extension settings is still
 * undecided (spike in Task 2 needs a live server to answer it), so both paths are
 * implemented: a PAT via the `configConnection` service connection when the pipeline
 * author supplied one, otherwise the job's own `System.AccessToken`. Both branches go
 * through `fetch` built by `buildFetch()`, not the global `fetch`: the task also targets
 * Node 16 agents (see `execution` in task.json), which have no global fetch.
 */
function buildConfigClient(): ConfigClient {
  const collectionUri = tl.getVariable('System.CollectionUri') ?? '';
  const connection = tl.getInput('configConnection');
  const fetch = buildFetch();

  if (connection) {
    const token =
      tl.getEndpointAuthorizationParameter(connection, 'password', true) ??
      tl.getEndpointAuthorizationParameter(connection, 'apitoken', true) ??
      '';
    return new ConfigClient({
      collectionUri,
      publisher: PUBLISHER,
      extensionId: EXTENSION_ID,
      auth: { mode: 'pat', token },
      fetch,
      log: (message) => tl.warning(message),
    });
  }

  return new ConfigClient({
    collectionUri,
    publisher: PUBLISHER,
    extensionId: EXTENSION_ID,
    auth: { mode: 'bearer', token: tl.getVariable('System.AccessToken') ?? '' },
    fetch,
    // A missing document falls back to defaults; say so, otherwise a mistyped publisher or an
    // uninstalled extension looks exactly like an administrator who has not configured anything.
    log: (message) => tl.warning(message),
  });
}

function registryCredentials(): { username?: string; password?: string } {
  const connection = tl.getInput('targetRegistryConnection');
  if (!connection) {
    return {};
  }
  return {
    username: tl.getEndpointAuthorizationParameter(connection, 'username', true),
    password: tl.getEndpointAuthorizationParameter(connection, 'password', true),
  };
}

async function main(): Promise<void> {
  try {
    const client = buildConfigClient();
    const runners = (await client.readDocument<RunnerConfig[]>('runners')) ?? [];
    const defaults = await client.readDocument<DefaultsConfig>('defaults');

    // Both passwords are entered once by an administrator directly into the settings
    // document (see RunnerConfig/DefaultsConfig doc comments) and are stored there in
    // plain text - the Extension Data Service is not a secret store. Registering them
    // with tl.setSecret here, as early as possible after they are read and before any
    // validation or scan step can log anything, makes the agent mask them out of every
    // log line for the rest of this run if either one is ever echoed anywhere.
    for (const runner of runners) {
      if (runner.registryPassword) {
        tl.setSecret(runner.registryPassword);
      }
    }
    if (defaults?.dbRegistryPassword) {
      tl.setSecret(defaults.dbRegistryPassword);
    }

    if (!defaults) {
      throw new Error(
        'The collection has no Trivy settings yet. Open Collection Settings > Trivy Scanner and configure the database mirror and at least one runner.',
      );
    }

    // The settings documents are hand-editable through the REST API, so validate them
    // before building a docker command from them. All issues are reported together,
    // not one per failed build.
    const issues = [
      ...validateDefaults(defaults),
      ...validateCatalog(runners),
      ...runners.flatMap((runner, index) =>
        validateRunner(runner).map((issue) => ({
          field: `runners[${index}].${issue.field}`,
          message: issue.message,
        })),
      ),
    ];
    if (issues.length > 0) {
      throw new Error(
        `The Trivy settings for this collection are invalid:\n${issues
          .map((issue) => `  ${issue.field}: ${issue.message}`)
          .join('\n')}`,
      );
    }

    const { gate } = await runScan({
      defaults,
      runners,
      inputs: readInputs(),
      agent: agentContext(),
      scanIndex: nextScanIndex(),
      processRunner: new ChildProcessRunner(),
      publisher: new Publisher(),
      credentials: registryCredentials(),
    });

    if (gate.outcome === 'failed') {
      tl.setResult(tl.TaskResult.Failed, gate.reason);
    } else if (gate.outcome === 'succeededWithIssues') {
      tl.setResult(tl.TaskResult.SucceededWithIssues, gate.reason);
    } else {
      tl.setResult(tl.TaskResult.Succeeded, gate.reason);
    }
  } catch (error) {
    tl.setResult(tl.TaskResult.Failed, (error as Error).message);
  }
}

void main();
