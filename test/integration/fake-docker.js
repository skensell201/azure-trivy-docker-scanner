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

// buildArgs (DockerCommand.ts) re-asserts --format/--output/--exit-code after any
// extraTrivyArgs, so --output can appear twice in a single invocation. A real CLI honors
// the last occurrence of a scalar flag (that is the entire reason the re-assertion after
// extraTrivyArgs works as a guard), so this must read from the end, not the first match --
// reading the first would silently pass this test even if the guard the production code
// relies on regressed to writing the FIRST --output instead of the last.
const outputFlag = args.lastIndexOf('--output');
if (outputFlag !== -1) {
  const containerPath = args[outputFlag + 1];
  const hostPath = path.join(context.workspace, containerPath.replace('/workspace/', ''));
  fs.mkdirSync(path.dirname(hostPath), { recursive: true });
  fs.writeFileSync(
    hostPath,
    JSON.stringify({
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
    }),
  );
}

process.exit(0);
