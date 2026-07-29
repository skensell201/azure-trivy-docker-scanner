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

// SIGKILL guarantees the direct child dies, but 'close' waits for every process
// holding the stdio pipes to let go -- including a descendant that inherited them
// (docker login spawns docker-credential-* helpers this way). This bounds the wait
// for that case: after the grace period we stop listening and report what we have.
const TIMEOUT_GRACE_PERIOD_MS = 1000;

export class ChildProcessRunner implements ProcessRunner {
  run(command: string, args: string[], options: RunOptions = {}): Promise<ProcessResult> {
    return new Promise((resolve) => {
      const child = spawn(command, args, { cwd: options.cwd });
      let stdout = '';
      let stderr = '';
      let timedOut = false;
      let graceTimer: NodeJS.Timeout | undefined;

      const timer =
        options.timeoutMs !== undefined
          ? setTimeout(() => {
              timedOut = true;
              child.kill('SIGKILL');
              graceTimer = setTimeout(() => {
                child.stdout.destroy();
                child.stderr.destroy();
                resolve({ exitCode: 124, stdout, stderr, timedOut });
              }, TIMEOUT_GRACE_PERIOD_MS);
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

      // Pipe reads can fail too (EIO, ECONNRESET, and Windows-specific pipe errors),
      // and this task also targets Windows agents. Without a listener here the 'error'
      // event throws synchronously and crashes the whole task process, the same risk
      // the stdin listener below guards against.
      child.stdout.on('error', (error: NodeJS.ErrnoException) => {
        stderr = appendErrorText(stderr, error.message);
      });
      child.stderr.on('error', (error: NodeJS.ErrnoException) => {
        stderr = appendErrorText(stderr, error.message);
      });

      // A child that exits before reading stdin makes the write fail with EPIPE.
      // Without this listener, the 'error' event on an EventEmitter with no listener
      // throws synchronously and crashes the whole task process, not just this run() --
      // exactly what would happen if `docker login --password-stdin` exited early.
      child.stdin.on('error', (error: NodeJS.ErrnoException) => {
        if (!isExpectedStdinError(error)) {
          stderr = appendErrorText(stderr, error.message);
        }
      });

      // 127 is used as a sentinel for every spawn failure -- ENOENT (not found),
      // EACCES (permission denied, which conventionally maps to 126), or anything
      // else -- the caller only needs the message, not a decoded, specific code.
      child.on('error', (error: Error) => {
        clearTimeout(timer);
        clearTimeout(graceTimer);
        resolve({ exitCode: 127, stdout, stderr: appendErrorText(stderr, error.message), timedOut });
      });

      child.on('close', (code) => {
        clearTimeout(timer);
        clearTimeout(graceTimer);
        resolve({ exitCode: code ?? (timedOut ? 124 : 1), stdout, stderr, timedOut });
      });

      // Always close stdin: this runner is non-interactive by design, and a child that
      // reads stdin to completion would otherwise block until the timeout for no reason.
      if (!child.stdin.destroyed) {
        try {
          child.stdin.end(options.stdin);
        } catch (error) {
          if (!isExpectedStdinError(error as NodeJS.ErrnoException)) {
            stderr = appendErrorText(stderr, (error as Error).message);
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

/**
 * Joins an out-of-band error message onto stderr already captured from the child's own
 * output. A bare concatenation can fuse the message onto the end of the last chunk
 * mid-word if that chunk did not already end in a newline.
 */
export function appendErrorText(existing: string, message: string): string {
  if (existing.length === 0 || existing.endsWith('\n')) {
    return existing + message;
  }
  return `${existing}\n${message}`;
}
