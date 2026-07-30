import * as fs from 'fs';
import * as tls from 'tls';
import * as tl from 'azure-pipelines-task-lib/task';
import { ConfigClient, FetchLike } from './ConfigClient';
import { createHttpFetch, httpFetch } from './httpFetch';
import { readInputs } from './inputs';
import { ChildProcessRunner } from './ProcessRunner';
import { Publisher } from './Publisher';
import { runScan } from './run';
import { selectOsCaBundlePath } from './trustSource';
import { validateCatalog, validateDefaults, validateRunner } from '../shared/validation';
import { AgentContext, DefaultsConfig, RunnerConfig } from '../shared/types';

/**
 * Well-known locations for the operating system's CA trust bundle, in the order they are tried.
 * These are the fallback used when the agent has no `--sslcacert` of its own (see `buildFetch`
 * below) - covering an on-premises install where nobody thought to pass that flag, but the OS
 * itself already trusts the internal PKI (as docker pulls from the internal registry prove).
 * Windows and macOS agents have none of these paths, land on Node's defaults, and that is fine.
 */
const OS_CA_BUNDLE_CANDIDATES = [
  '/etc/ssl/certs/ca-certificates.crt', // Debian, Ubuntu, Alpine
  '/etc/pki/tls/certs/ca-bundle.crt', // RHEL, CentOS, Fedora
  '/etc/ssl/ca-bundle.pem', // SUSE
];

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
 * Builds the CA list to hand `createHttpFetch`: Node's own bundled roots *plus* one extra trusted
 * bundle, never the extra bundle alone.
 *
 * This is the detail that is easy to "simplify" back into a bug: `https.request`'s `ca` option
 * *replaces* Node's bundled root store rather than adding to it. Passing it only the agent's (or
 * the OS's) CA bundle would silently drop every root Node ships - and if that particular bundle
 * happened to be incomplete (an internal-only distribution missing a root a public host needs, or
 * simply a distro whose maintainers pruned something), TLS to unrelated public hosts would start
 * failing while everything looked like it had been "fixed". `tls.rootCertificates` (an array of
 * PEM strings, available since Node 12) is Node's own bundled store; concatenating it with the
 * extra bundle and handing `https.request` the whole array - which it accepts, per its own type -
 * is the union, not a replacement.
 */
function unionWithNodeRoots(extra: Buffer): Array<string | Buffer> {
  return [...tls.rootCertificates, extra];
}

/**
 * Chooses which CA (if any) this task's own HTTPS calls should trust, beyond Node's bundled roots,
 * so a "runners" settings read does not fail with "unable to get local issuer certificate" on a
 * server behind an internal PKI. Tried in order:
 *
 * 1. The agent's own `--sslcacert` configuration (`tl.getHttpCertConfiguration().caFile`) - the
 *    same CA the .NET agent itself was explicitly told to trust. An administrator who set this up
 *    meant it, so it always wins when present.
 * 2. Failing that, the operating system's own trust bundle, at whichever of the well-known
 *    locations in `OS_CA_BUNDLE_CANDIDATES` exists first. This is the case this fallback exists
 *    for: an on-premises agent whose OS already trusts the internal CA (docker pulls from the
 *    internal registry already prove that) but that was never configured with `--sslcacert`,
 *    because Node on Linux does not consult the OS trust store on its own - it carries its own
 *    bundled roots instead.
 * 3. Failing that, Node's defaults, unchanged. Windows and macOS agents have none of the
 *    OS_CA_BUNDLE_CANDIDATES paths and always land here; that is expected, not an error, so no
 *    warning is logged for it - a warning belongs only where something *was* configured (or
 *    found) and could not be used.
 *
 * `certFile`/`keyFile` (a client certificate, i.e. mutual TLS) are deliberately ignored: that is a
 * different feature from trusting a CA, nobody has asked for it, and wiring it through only
 * partway (e.g. without also handling `passphrase`/`certArchiveFile` correctly) would be worse
 * than not touching it at all.
 *
 * Every path here logs, via `tl.debug`, which of the three sources was actually used - so when
 * someone does hit a certificate problem, the log can answer "which trust store was in play"
 * instead of leaving that to be guessed at.
 */
function buildFetch(): FetchLike {
  const certConfiguration = tl.getHttpCertConfiguration();

  if (certConfiguration?.caFile) {
    try {
      const ca = fs.readFileSync(certConfiguration.caFile);
      tl.debug(
        `buildFetch: trusting the agent's configured CA file (${certConfiguration.caFile}), ` +
          "in addition to Node's bundled roots.",
      );
      return createHttpFetch({ ca: unionWithNodeRoots(ca) });
    } catch (error) {
      // A CA file that cannot be read must not fail the whole task: the request may well succeed
      // anyway (a proxy or load balancer terminating TLS with a publicly-trusted cert, for
      // instance). Something was explicitly configured here and could not be used, so - unlike
      // the OS-bundle and Node-defaults paths below - this does warrant a warning naming the path.
      tl.warning(
        `The agent's configured CA file (${certConfiguration.caFile}) could not be read: ` +
          `${(error as Error).message}. Continuing with Node's default trusted roots; the request ` +
          'may still succeed.',
      );
      return httpFetch;
    }
  }

  const osBundlePath = selectOsCaBundlePath(OS_CA_BUNDLE_CANDIDATES, fs.existsSync);
  if (osBundlePath) {
    try {
      const ca = fs.readFileSync(osBundlePath);
      tl.debug(
        `buildFetch: no agent CA configured; trusting the OS trust bundle at ${osBundlePath}, ` +
          "in addition to Node's bundled roots.",
      );
      return createHttpFetch({ ca: unionWithNodeRoots(ca) });
    } catch {
      // Exists (per fs.existsSync) but could not be read - a permissions oddity, or a race with
      // deletion. Nobody configured this path; it was merely found, so per the rule above it does
      // not get a warning. Node's defaults are exactly as usable as if the path had never existed.
    }
  }

  tl.debug(
    "buildFetch: no agent CA configured and no OS trust bundle found; using Node's default " +
      'trusted roots only.',
  );
  return httpFetch;
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
