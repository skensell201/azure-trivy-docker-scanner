import { ChildProcessRunner } from '../ProcessRunner';

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
});
