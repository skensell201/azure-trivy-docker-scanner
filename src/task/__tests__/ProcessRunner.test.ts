import * as fs from 'fs';
import * as os from 'os';
import { ChildProcessRunner, appendErrorText } from '../ProcessRunner';

const runner = new ChildProcessRunner();

describe('ChildProcessRunner', () => {
  it('captures stdout and a zero exit code', async () => {
    const result = await runner.run(process.execPath, ['-e', 'process.stdout.write("hello")']);
    expect(result).toMatchObject({ exitCode: 0, stdout: 'hello', timedOut: false });
  });

  it('captures stderr and a non-zero exit code without throwing', async () => {
    const result = await runner.run(process.execPath, [
      '-e',
      'process.stderr.write("boom"); process.exit(3)',
    ]);
    expect(result.exitCode).toBe(3);
    expect(result.stderr).toContain('boom');
  });

  it('kills a process that outlives its timeout and reports it', async () => {
    const result = await runner.run(process.execPath, ['-e', 'setTimeout(() => {}, 10000)'], {
      timeoutMs: 200,
    });
    expect(result.timedOut).toBe(true);
    expect(result.exitCode).not.toBe(0);
  });

  it('writes stdin to the process when provided', async () => {
    const result = await runner.run(
      process.execPath,
      ['-e', 'process.stdin.on("data", (d) => process.stdout.write("got:" + d))'],
      { stdin: 'secret' },
    );
    expect(result.stdout).toBe('got:secret');
  });

  it('reports a missing executable as a failed result instead of rejecting', async () => {
    const result = await runner.run('definitely-not-a-real-binary-9182', []);
    expect(result.exitCode).not.toBe(0);
    expect(result.stderr).toMatch(/ENOENT|not found/i);
  });

  // Pins listening on 'close' rather than 'exit': 'exit' can fire before a large
  // pending write has drained from the pipe, which would truncate the captured output.
  it('captures output in full when the child writes a lot and exits immediately', async () => {
    const size = 5 * 1024 * 1024;
    const result = await runner.run(process.execPath, [
      '-e',
      `require('fs').writeSync(1, 'x'.repeat(${size})); process.exit(0)`,
    ]);
    expect(result.stdout.length).toBe(size);
  });

  // Pins the `code ?? (timedOut ? 124 : 1)` mapping: a killed process reports a null
  // exit code, and 124 (the conventional timeout exit code) lets a caller tell a real
  // timeout apart from an ordinary process failure without inspecting `timedOut` too.
  it('reports exit code 124 for a process killed on timeout', async () => {
    const result = await runner.run(process.execPath, ['-e', 'setTimeout(() => {}, 10000)'], {
      timeoutMs: 200,
    });
    expect(result.exitCode).toBe(124);
  });

  // A child that exits before reading stdin makes the write fail with EPIPE. Without
  // an error listener on child.stdin this throws synchronously and crashes the whole
  // process (not just this run() call) -- exactly the risk for a later `docker login
  // --password-stdin` caller if docker exits before consuming the piped password.
  it('resolves normally instead of crashing when the child exits before reading a large stdin payload', async () => {
    const payload = 'x'.repeat(2 * 1024 * 1024); // 2MB, well past the OS pipe buffer
    const result = await runner.run(process.execPath, ['-e', 'process.exit(0)'], {
      stdin: payload,
    });
    expect(result.exitCode).toBe(0);
  });

  // Listening on 'close' means waiting for every process holding the stdio pipes to let
  // go, including descendants -- exactly what `docker login` does by spawning a
  // docker-credential-* helper. Before the grace timer, this took as long as the
  // grandchild did (measured ~15s here) instead of respecting the 500ms timeout.
  it('resolves promptly on timeout even when a descendant keeps stdout open', async () => {
    const script =
      'const cp=require("child_process");' +
      'const g=cp.spawn(process.execPath,["-e","setTimeout(()=>{},15000)"],' +
      '{stdio:["ignore",1,2],detached:true});g.unref();' +
      'setTimeout(()=>{},10000);';
    const started = Date.now();
    const result = await runner.run(process.execPath, ['-e', script], { timeoutMs: 500 });
    const elapsedMs = Date.now() - started;
    expect(result.timedOut).toBe(true);
    expect(result.exitCode).toBe(124);
    expect(elapsedMs).toBeLessThan(3000);
  }, 10000);

  // Reviewer-verified discriminator: passes with 'close', fails with an empty string
  // if swapped for 'exit'. No timeout is involved, so the Fix 1 grace timer must not
  // interfere with this case.
  it('captures output a detached descendant writes after the direct child exits', async () => {
    const script =
      'const cp=require("child_process");' +
      'const g=cp.spawn(process.execPath,["-e","setTimeout(()=>{process.stdout.write(\\"late\\")},300)"],' +
      '{stdio:["ignore",1,2],detached:true});g.unref();process.exit(0);';
    const result = await runner.run(process.execPath, ['-e', script]);
    expect(result.stdout).toBe('late');
  });

  // SIGKILL cannot be caught or ignored; SIGTERM can. The direct child here installs a
  // no-op SIGTERM handler, so it only dies if the implementation truly sends SIGKILL --
  // if it sent SIGTERM instead, this test would only resolve via the Fix 1 grace timer,
  // roughly a full grace period later, which the elapsed-time bound below catches.
  it('sends SIGKILL rather than a signal the child could ignore', async () => {
    const script = 'process.on("SIGTERM", () => {}); setTimeout(() => {}, 10000);';
    const started = Date.now();
    const result = await runner.run(process.execPath, ['-e', script], { timeoutMs: 300 });
    const elapsedMs = Date.now() - started;
    expect(result.timedOut).toBe(true);
    expect(elapsedMs).toBeLessThan(900);
  }, 5000);

  it('streams stdout chunks live via onStdout as they arrive', async () => {
    const chunks: string[] = [];
    const result = await runner.run(
      process.execPath,
      ['-e', 'process.stdout.write("a"); process.stdout.write("b")'],
      { onStdout: (chunk) => chunks.push(chunk) },
    );
    expect(chunks.join('')).toBe(result.stdout);
    expect(result.stdout).toBe('ab');
  });

  it('spawns the child in the requested working directory', async () => {
    const cwd = fs.realpathSync(os.tmpdir());
    const result = await runner.run(process.execPath, ['-e', 'process.stdout.write(process.cwd())'], {
      cwd,
    });
    expect(result.stdout).toBe(cwd);
  });

  // Nothing stops a future edit from dropping the clearTimeout call in the close
  // handler, which would leave a long-lived timer holding the event loop open at the
  // end of every build even though the process already exited.
  it('resolves promptly for a fast process even under a long timeout', async () => {
    const started = Date.now();
    const result = await runner.run(process.execPath, ['-e', 'process.exit(0)'], {
      timeoutMs: 600000,
    });
    const elapsedMs = Date.now() - started;
    expect(result.exitCode).toBe(0);
    expect(elapsedMs).toBeLessThan(2000);
  });

  it('treats a timeoutMs of 0 as an immediate timeout rather than "no timeout"', async () => {
    const result = await runner.run(process.execPath, ['-e', 'setTimeout(() => {}, 10000)'], {
      timeoutMs: 0,
    });
    expect(result.timedOut).toBe(true);
  }, 5000);

  it('closes stdin immediately when none is provided, so a child reading it does not block', async () => {
    const script =
      'process.stdin.resume();' + 'process.stdin.on("end", () => process.stdout.write("ended"))';
    const result = await runner.run(process.execPath, ['-e', script]);
    expect(result.stdout).toBe('ended');
  });
});

describe('appendErrorText', () => {
  it('appends directly when nothing has been captured yet', () => {
    expect(appendErrorText('', 'boom')).toBe('boom');
  });

  it('inserts a newline so an appended message does not fuse onto the last chunk', () => {
    expect(appendErrorText('partial', 'boom')).toBe('partial\nboom');
  });

  it('does not add a second newline when the captured text already ends with one', () => {
    expect(appendErrorText('partial\n', 'boom')).toBe('partial\nboom');
  });
});
