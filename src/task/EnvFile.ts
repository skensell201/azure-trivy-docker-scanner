import * as fs from 'fs';
import * as path from 'path';

export function writeEnvFile(dir: string, name: string, env: Record<string, string>): string {
  const lines = Object.entries(env).map(([key, value]) => {
    if (value.includes('\n')) {
      throw new Error(`Value of ${key} contains a newline, which a docker env-file cannot express.`);
    }
    return `${key}=${value}`;
  });

  const file = path.join(dir, `trivy-${name}.env`);
  fs.writeFileSync(file, `${lines.join('\n')}\n`, { mode: 0o600 });
  fs.chmodSync(file, 0o600);
  return file;
}

export function removeEnvFile(file: string): void {
  fs.rmSync(file, { force: true });
}
