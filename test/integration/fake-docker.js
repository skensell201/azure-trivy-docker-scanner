#!/usr/bin/env node
// Stands in for the docker CLI: records the argv it was invoked with (proving what
// actually reached a process, not just what DockerCommand built in memory) and writes a
// canned trivy report to whatever path the scan asked for.
//
// Where to write the log/report is passed through a JSON "context" file on disk, keyed
// by this process's ppid, rather than through environment variables. Under ts-jest, the
// `process.env` a test mutates lives in the test file's own vm context; Node's real
// `child_process.spawn()` (invoked by ChildProcessRunner, a plain Node module shared
// across contexts) sources its default `env` from the *outer* real process instead, so a
// spawned child never actually sees env vars a test set on the sandboxed `process.env` --
// confirmed by spawning a bare child with no explicit `env` option and observing it read
// back `undefined` for a variable the test had just set. `process.pid`/`process.ppid` are
// plain OS-level integers rather than object properties Jest could sandbox, so they are
// the one thing guaranteed to match between the test process and this script.
const fs = require('fs');
const os = require('os');
const path = require('path');

function contextPath() {
  return path.join(os.tmpdir(), `trivy-fake-docker-context-${process.ppid}.json`);
}

const context = JSON.parse(fs.readFileSync(contextPath(), 'utf8'));

const args = process.argv.slice(2);
fs.appendFileSync(context.log, JSON.stringify(args) + '\n');

// Mirrors what the real docker binary does with --env-file: read it and expose its
// content as the "container environment". This is how the credentials test proves
// TRIVY_USERNAME/TRIVY_PASSWORD travel through the env file and never touch argv, which
// the docker-calls.log above also records for that same check.
const envFileFlag = args.indexOf('--env-file');
if (envFileFlag !== -1 && context.envLog) {
  const envFileContent = fs.readFileSync(args[envFileFlag + 1], 'utf8');
  fs.appendFileSync(context.envLog, envFileContent);
}

if (args.includes('version')) {
  process.stdout.write(
    '{"Version":"0.58.1","VulnerabilityDB":{"UpdatedAt":"2026-07-28T06:11:53Z"}}',
  );
  process.exit(0);
}

const CANNED_REPORT = JSON.stringify({
  SchemaVersion: 2,
  ArtifactName: 'app:1.4.2',
  Results: [
    {
      Target: 'app:1.4.2',
      Vulnerabilities: [
        { VulnerabilityID: 'CVE-2024-21626', PkgName: 'runc', Severity: 'HIGH', Title: 'escape' },
      ],
    },
  ],
});

/**
 * buildArgs (DockerCommand.ts) re-asserts --format/--output/--exit-code after any
 * extraTrivyArgs, so --output can appear twice in a single invocation. A real CLI honors
 * the last occurrence of a scalar flag (that is the entire reason the re-assertion after
 * extraTrivyArgs works as a guard), so this must read from the end, not the first match --
 * reading the first would silently pass this test even if the guard the production code
 * relies on regressed to writing the FIRST --output instead of the last.
 */
function outputPathFrom(commandArgs) {
  const outputFlag = commandArgs.lastIndexOf('--output');
  return outputFlag === -1 ? undefined : commandArgs[outputFlag + 1];
}

const subcommand = args[0];

if (subcommand === 'run') {
  // 'mount' mode: unchanged from before copy mode existed. The sources are (in a real
  // daemon) bind-mounted onto /workspace, so the container path this run was asked to
  // write its report to maps directly onto a path under the real host workspace.
  const containerPath = outputPathFrom(args);
  if (containerPath !== undefined) {
    const hostPath = path.join(context.workspace, containerPath.replace('/workspace/', ''));
    fs.mkdirSync(path.dirname(hostPath), { recursive: true });
    fs.writeFileSync(hostPath, CANNED_REPORT);
  }
  process.exit(0);
}

// -- 'copy' mode: create / cp / start / rm --------------------------------------------
//
// Real docker keeps a container's filesystem alive between `docker create`, `docker
// start` and the `docker cp` that follows it, until `docker rm` deletes it -- but each of
// those is a *separate process invocation* of this script, with no memory of the others.
// A directory on disk, keyed by the container name (unique enough within one test's own
// workspace-scoped context), stands in for that container filesystem so `start` can see
// what `create` was asked to do, and `cp ... out` can see what `start` "wrote".
function containerStateDir(name) {
  return path.join(os.tmpdir(), 'trivy-fake-containers', name);
}

if (subcommand === 'create') {
  const name = args[args.indexOf('--name') + 1];
  const dir = containerStateDir(name);
  fs.mkdirSync(dir, { recursive: true });
  // Persists the full create argv so the later `start` call -- a different process --
  // can find --output (and everything else) without re-parsing docker's own semantics.
  fs.writeFileSync(path.join(dir, 'create-args.json'), JSON.stringify(args));
  process.exit(0);
}

if (subcommand === 'cp') {
  const source = args[1];
  const destination = args[2];
  const destinationIsContainer = destination.includes(':');
  const sourceIsContainer = source.includes(':');

  if (destinationIsContainer) {
    // Copy IN (`docker cp <sourcesDir> <name>:/workspace`): this fake never actually
    // scans real files, so there is nothing to place -- the call is only recorded above.
    // What matters for the tests is that this call happens at all, and with no `-v`.
    process.exit(0);
  }

  if (sourceIsContainer) {
    // Copy OUT (`docker cp <name>:<containerPath> <hostPath>`): read back whatever
    // `start` wrote into this container's fake filesystem and place it at the host path,
    // exactly like a real `docker cp` retrieving a file over the API rather than a mount.
    const separator = source.indexOf(':');
    const name = source.slice(0, separator);
    const containerPath = source.slice(separator + 1);
    const virtualPath = path.join(containerStateDir(name), containerPath.replace(/^\/+/, ''));
    fs.mkdirSync(path.dirname(destination), { recursive: true });
    fs.copyFileSync(virtualPath, destination);
  }
  process.exit(0);
}

if (subcommand === 'start') {
  const name = args[args.indexOf('-a') + 1] ?? args[1];
  const dir = containerStateDir(name);
  const createArgs = JSON.parse(fs.readFileSync(path.join(dir, 'create-args.json'), 'utf8'));
  const containerPath = outputPathFrom(createArgs);
  if (containerPath !== undefined) {
    const virtualPath = path.join(dir, containerPath.replace(/^\/+/, ''));
    fs.mkdirSync(path.dirname(virtualPath), { recursive: true });
    fs.writeFileSync(virtualPath, CANNED_REPORT);
  }
  process.exit(0);
}

if (subcommand === 'rm') {
  const name = args[args.length - 1];
  fs.rmSync(containerStateDir(name), { recursive: true, force: true });
  process.exit(0);
}

process.exit(0);
