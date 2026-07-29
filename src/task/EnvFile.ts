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
  const content = `${lines.join('\n')}\n`;

  // Opened by hand instead of the simpler fs.writeFileSync(file, content, { mode })
  // overload: that overload opens without O_NOFOLLOW, so it follows a symlink if one
  // is already sitting at `file`. Since this file holds registry credentials, a
  // pre-planted symlink would make us write secrets through it and then chmod
  // whatever it points at. O_NOFOLLOW makes the open itself fail on a symlink instead.
  const fd = fs.openSync(
    file,
    fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_TRUNC | fs.constants.O_NOFOLLOW,
    0o600,
  );
  try {
    fs.writeSync(fd, content);
  } finally {
    fs.closeSync(fd);
  }
  fs.chmodSync(file, 0o600);
  return file;
}

export function removeEnvFile(file: string): void {
  fs.rmSync(file, { force: true });
}
