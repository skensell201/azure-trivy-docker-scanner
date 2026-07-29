import { spawn } from 'child_process';

export interface RunOptions {
  timeoutMs?: number;
  stdin?: string;
  cwd?: string;
  onStdout?: (chunk: string) => void;
}

export interface ProcessResult {
  exitCode: number;
  stdout: string;
  stderr: string;
  timedOut: boolean;
}

export interface ProcessRunner {
  run(command: string, args: string[], options?: RunOptions): Promise<ProcessResult>;
}

export class ChildProcessRunner implements ProcessRunner {
  run(command: string, args: string[], options: RunOptions = {}): Promise<ProcessResult> {
    return new Promise((resolve) => {
      const child = spawn(command, args, { cwd: options.cwd });
      let stdout = '';
      let stderr = '';
      let timedOut = false;

      const timer = options.timeoutMs
        ? setTimeout(() => {
            timedOut = true;
            child.kill('SIGKILL');
          }, options.timeoutMs)
        : undefined;

      // captured stdout/stderr are complete only if the child flushes before it exits:
      // 'close' (unlike 'exit') waits for the stdio streams to end, but it cannot pull
      // data out of a pipe the child itself never wrote before calling process.exit().
      child.stdout.on('data', (chunk: Buffer) => {
        const text = chunk.toString();
        stdout += text;
        options.onStdout?.(text);
      });
      child.stderr.on('data', (chunk: Buffer) => {
        stderr += chunk.toString();
      });

      // A child that exits before reading stdin makes the write fail with EPIPE.
      // Without this listener, the 'error' event on an EventEmitter with no listener
      // throws synchronously and crashes the whole task process, not just this run() --
      // exactly what would happen if `docker login --password-stdin` exited early.
      child.stdin.on('error', (error: NodeJS.ErrnoException) => {
        if (!isExpectedStdinError(error)) {
          stderr += error.message;
        }
      });

      child.on('error', (error: Error) => {
        clearTimeout(timer);
        resolve({ exitCode: 127, stdout, stderr: `${stderr}${error.message}`, timedOut });
      });

      child.on('close', (code) => {
        clearTimeout(timer);
        resolve({ exitCode: code ?? (timedOut ? 124 : 1), stdout, stderr, timedOut });
      });

      if (options.stdin !== undefined && !child.stdin.destroyed) {
        try {
          child.stdin.end(options.stdin);
        } catch (error) {
          if (!isExpectedStdinError(error as NodeJS.ErrnoException)) {
            stderr += (error as Error).message;
          }
        }
      }
    });
  }
}

/**
 * EPIPE and ERR_STREAM_DESTROYED are the expected shape of "the child exited before
 * reading its input" -- the process's own exit code and stderr already describe what
 * happened, so these are not reported again. Anything else is a genuine stdin failure
 * and must reach the caller instead of vanishing.
 */
function isExpectedStdinError(error: NodeJS.ErrnoException): boolean {
  return error.code === 'EPIPE' || error.code === 'ERR_STREAM_DESTROYED';
}
