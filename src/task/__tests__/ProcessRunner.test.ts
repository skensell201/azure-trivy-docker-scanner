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
});
