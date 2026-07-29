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

      child.stdout.on('data', (chunk: Buffer) => {
        const text = chunk.toString();
        stdout += text;
        options.onStdout?.(text);
      });
      child.stderr.on('data', (chunk: Buffer) => {
        stderr += chunk.toString();
      });

      child.on('error', (error: Error) => {
        clearTimeout(timer);
        resolve({ exitCode: 127, stdout, stderr: `${stderr}${error.message}`, timedOut });
      });

      child.on('close', (code) => {
        clearTimeout(timer);
        resolve({ exitCode: code ?? (timedOut ? 124 : 1), stdout, stderr, timedOut });
      });

      if (options.stdin !== undefined) {
        child.stdin.end(options.stdin);
      }
    });
  }
}
