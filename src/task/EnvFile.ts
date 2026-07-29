import * as fs from 'fs';
import * as path from 'path';

const SAFE_NAME = /^[A-Za-z0-9_-]+$/;

export function writeEnvFile(dir: string, name: string, env: Record<string, string>): string {
  if (!SAFE_NAME.test(name)) {
    throw new Error(
      `Invalid env file name "${name}": expected only letters, digits, dashes and underscores.`,
    );
  }

  const lines = Object.entries(env).map(([key, value]) => {
    if (/[\r\n]/.test(key)) {
      throw new Error(`Key "${key}" contains a newline, which a docker env-file cannot express.`);
    }
    if (/[\r\n]/.test(value)) {
      throw new Error(
        `Value of ${key} contains a newline or carriage return, which a docker env-file cannot express.`,
      );
    }
    return `${key}=${value}`;
  });

  const file = path.join(dir, `trivy-${name}.env`);
  const content = `${lines.join('\n')}\n`;

  // Unlink any existing name at `file` before creating a fresh one with
  // O_CREAT|O_EXCL. This is what makes a legitimate second call with the same
  // (dir, name) behave as an overwrite, and it is also what protects against a
  // symlink OR a hardlink pre-planted at this exact path:
  //  - a symlink would otherwise be followed on open (also independently rejected by
  //    O_NOFOLLOW below, and by O_EXCL itself: POSIX requires O_CREAT|O_EXCL to fail
  //    with EEXIST on an existing symlink regardless of its target);
  //  - a hardlink is not a symlink at all - O_NOFOLLOW does not see it - so opening and
  //    truncating that name in place would write secrets straight into whatever inode
  //    an attacker already had a second name for, and even a descriptor-based chmod
  //    afterward would loosen permissions on that shared inode.
  // Unlinking first and creating with O_EXCL guarantees we always write into a
  // brand-new, uniquely-owned inode: never one that existed under any other name a
  // moment ago.
  try {
    fs.unlinkSync(file);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
      throw error;
    }
  }

  const fd = fs.openSync(
    file,
    fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW,
    0o600,
  );
  try {
    // fchmodSync runs on the open descriptor - no path lookup, so no window for a
    // symlink or hardlink swap - and it runs BEFORE writeSync so the secret content is
    // never written while the descriptor could be at a wider mode than 0600 (the mode
    // passed to open() above is still subject to the process umask, which can only
    // narrow it further, not guarantee it lands on exactly 0600).
    fs.fchmodSync(fd, 0o600);
    fs.writeSync(fd, content);
  } finally {
    fs.closeSync(fd);
  }
  return file;
}

/**
 * Removes the env file, never throwing: this is called from a caller's `finally`
 * block after a scan, and a thrown delete error there would replace the real scan
 * failure while the credentials file stays on disk. `force: true` on fs.rmSync only
 * swallows ENOENT - EISDIR, EACCES, EPERM, a locked file, or a bad argument type would
 * all still throw - so every failure is caught here. Returns whether the file is gone
 * (removed, or was already absent) and, on failure, reports why via `onWarning` so a
 * leftover credentials file is never silent.
 */
export function removeEnvFile(file: string, onWarning?: (message: string) => void): boolean {
  try {
    fs.rmSync(file, { force: true });
    return true;
  } catch (error) {
    onWarning?.(
      `Failed to remove trivy env file "${String(file)}": ${describeError(error)}. ` +
        'A registry credentials file may remain on disk.',
    );
    return false;
  }
}

function describeError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
