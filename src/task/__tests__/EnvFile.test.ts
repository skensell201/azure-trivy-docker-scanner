import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

// jest.spyOn(fs, ...) cannot redefine these properties on this Node/ts-jest
// combination: `import * as fs from 'fs'` is compiled to a frozen ES module
// namespace object, not the live, configurable module.exports that plain
// require('fs') returns. jest.mock replaces the module at require-resolution time
// instead of trying to redefine a property on that frozen object, so it works where
// spyOn does not. Everything not listed here passes through to the real
// implementation; only the four calls this suite needs to observe are wrapped.
jest.mock('fs', () => {
  const actual = jest.requireActual<typeof fs>('fs');
  return {
    ...actual,
    writeSync: jest.fn(actual.writeSync),
    fchmodSync: jest.fn(actual.fchmodSync),
    chmodSync: jest.fn(actual.chmodSync),
    openSync: jest.fn(actual.openSync),
  };
});

import { removeEnvFile, writeEnvFile } from '../EnvFile';

describe('writeEnvFile', () => {
  let dir: string;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'envfile-'));
  });

  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('writes one KEY=value line per entry', () => {
    const file = writeEnvFile(dir, 'scan-0', { TRIVY_DB_REPOSITORY: 'reg/db:2', TRIVY_USERNAME: 'svc' });
    expect(fs.readFileSync(file, 'utf8')).toBe('TRIVY_DB_REPOSITORY=reg/db:2\nTRIVY_USERNAME=svc\n');
  });

  it('creates the file readable only by the owner', () => {
    const file = writeEnvFile(dir, 'scan-0', { A: 'b' });
    expect(fs.statSync(file).mode & 0o777).toBe(0o600);
  });

  it('rejects a value containing a newline because docker env-file cannot express it', () => {
    expect(() => writeEnvFile(dir, 'scan-0', { A: 'line1\nline2' })).toThrow(/newline/i);
  });

  it('removes the file and stays silent when it is already gone', () => {
    const file = writeEnvFile(dir, 'scan-0', { A: 'b' });
    removeEnvFile(file);
    expect(fs.existsSync(file)).toBe(false);
    expect(() => removeEnvFile(file)).not.toThrow();
  });

  // The docker env-file format splits each line on the first "=" only, so a value
  // containing "=" (a common shape for opaque tokens or key=value secrets) must pass
  // through unescaped rather than being rejected or truncated at the first occurrence.
  it('preserves a value containing an equals sign', () => {
    const file = writeEnvFile(dir, 'scan-0', { TRIVY_PASSWORD: 'p@ss=word=2' });
    expect(fs.readFileSync(file, 'utf8')).toBe('TRIVY_PASSWORD=p@ss=word=2\n');
  });

  it('writes an explicitly empty value as a bare KEY= line', () => {
    const file = writeEnvFile(dir, 'scan-0', { TRIVY_EMPTY: '' });
    expect(fs.readFileSync(file, 'utf8')).toBe('TRIVY_EMPTY=\n');
  });

  // The file path is derived only from (dir, name), so a second call with the same
  // name must land on the same path. Overwriting is the correct behavior here: this
  // is a per-scan scratch file the caller rewrites and removes, not an append log.
  it('overwrites the file on a second call with the same name', () => {
    const first = writeEnvFile(dir, 'scan-0', { A: 'first' });
    const second = writeEnvFile(dir, 'scan-0', { A: 'second' });
    expect(second).toBe(first);
    expect(fs.readFileSync(second, 'utf8')).toBe('A=second\n');
  });

  // A second call unlinks whatever was at this path before recreating it, so a
  // previously-widened mode never survives on its own merit. fchmodSync still matters
  // here: the mode passed to open() is subject to the process umask, which can only
  // narrow it further, not guarantee it lands on exactly 0600. This pins the end state
  // regardless of what the file's permissions were set to before this call.
  it('restores 0600 on a second call even if the file was widened in between', () => {
    const file = writeEnvFile(dir, 'scan-0', { A: 'first' });
    fs.chmodSync(file, 0o644);
    writeEnvFile(dir, 'scan-0', { A: 'second' });
    expect(fs.statSync(file).mode & 0o777).toBe(0o600);
  });

  // A symlink pre-planted at the env file path (e.g. by another process sharing the
  // temp directory) must never be written through or have its target's permissions
  // touched. writeEnvFile unlinks whatever name is at the target path before creating
  // a fresh file with O_CREAT|O_EXCL, so the symlink itself is removed and a brand new,
  // unrelated file takes its place - the link's original target is never opened at all.
  it('replaces a symlink planted at the target path instead of writing through it, leaving its target untouched', () => {
    const outside = path.join(dir, 'outside.txt');
    fs.writeFileSync(outside, 'do not touch');

    const file = writeEnvFile(dir, 'scan-0', { A: 'placeholder' });
    fs.rmSync(file);
    fs.symlinkSync(outside, file);

    const result = writeEnvFile(dir, 'scan-0', { A: 'real-secret' });

    expect(fs.lstatSync(result).isSymbolicLink()).toBe(false);
    expect(fs.readFileSync(result, 'utf8')).toBe('A=real-secret\n');
    expect(fs.statSync(result).mode & 0o777).toBe(0o600);
    expect(fs.readFileSync(outside, 'utf8')).toBe('do not touch');
  });

  // O_NOFOLLOW rejects a symlink, but a hardlink is not a symlink - it is a second name
  // for the same inode as some victim file, and O_NOFOLLOW cannot see it. Opening that
  // name with O_TRUNC would truncate and overwrite the victim's actual content, and
  // even a descriptor-based fchmodSync afterward would loosen permissions on the
  // victim's inode. Unlinking the name first (see writeEnvFile) removes only this one
  // link - the victim's own name and content are never touched - before a fresh,
  // uniquely-owned inode is created with O_EXCL.
  it('replaces a hardlink planted at the target path instead of writing through the shared inode', () => {
    const victim = path.join(dir, 'victim.txt');
    fs.writeFileSync(victim, 'do not touch');

    const file = writeEnvFile(dir, 'scan-0', { A: 'placeholder' });
    fs.rmSync(file);
    fs.linkSync(victim, file);
    expect(fs.statSync(victim).nlink).toBe(2);

    const result = writeEnvFile(dir, 'scan-0', { A: 'real-secret' });

    expect(fs.statSync(victim).nlink).toBe(1);
    expect(fs.readFileSync(victim, 'utf8')).toBe('do not touch');
    expect(fs.readFileSync(result, 'utf8')).toBe('A=real-secret\n');
    expect(fs.statSync(result).mode & 0o777).toBe(0o600);
  });

  // Nothing pinned the order of narrowing vs. writing before: a mutant that swaps
  // fchmodSync and writeSync keeps every other test green, because the end state
  // (content + 0600) looks the same either way. `clearMocks: true` resets these mock
  // functions' call history before every test, so `invocationCallOrder` reflects only
  // this test's single writeEnvFile call: the secret must never be written while the
  // descriptor could still be at a wider mode than 0600.
  it('narrows the descriptor to 0600 before writing the secret content', () => {
    writeEnvFile(dir, 'scan-0', { A: 'b' });

    const chmodOrder = (fs.fchmodSync as jest.Mock).mock.invocationCallOrder[0];
    const writeOrder = (fs.writeSync as jest.Mock).mock.invocationCallOrder[0];
    expect(chmodOrder).toBeLessThan(writeOrder);
  });

  // Mutating fchmodSync(fd, ...) back to chmodSync(file, ...) reintroduces the
  // path-re-resolution window closed in an earlier round, but every assertion above
  // is satisfied either way since both calls end up setting the same bits. Pin the
  // descriptor-based call directly: chmodSync must never be invoked by this module.
  it('never calls the path-based chmodSync', () => {
    writeEnvFile(dir, 'scan-0', { A: 'b' });

    expect(fs.chmodSync).not.toHaveBeenCalled();
  });

  // fchmodSync narrows the mode to 0600 regardless of what was requested at creation,
  // so a mutant that widens the open() mode argument to 0666 is invisible to the final
  // fs.statSync check. Pin the creation-time argument directly so a momentarily-wider
  // creation mode cannot slip back in unnoticed.
  it('requests a 0600 mode when creating the file', () => {
    writeEnvFile(dir, 'scan-0', { A: 'b' });

    expect(fs.openSync).toHaveBeenCalledWith(expect.any(String), expect.any(Number), 0o600);
  });

  it('rejects a key containing a newline because docker env-file cannot express it', () => {
    expect(() => writeEnvFile(dir, 'scan-0', { 'A\nB': 'b' })).toThrow(/newline/i);
  });

  it('rejects a value containing a lone carriage return', () => {
    expect(() => writeEnvFile(dir, 'scan-0', { A: 'line1\rline2' })).toThrow(/newline|carriage return/i);
  });

  it('rejects a name that is not safe to embed in a file path', () => {
    expect(() => writeEnvFile(dir, '../escape', { A: 'b' })).toThrow(/name/i);
    expect(() => writeEnvFile(dir, 'has/slash', { A: 'b' })).toThrow(/name/i);
  });
});

describe('removeEnvFile', () => {
  let dir: string;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'envfile-remove-'));
  });

  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('returns true when it removes an existing file', () => {
    const file = writeEnvFile(dir, 'scan-0', { A: 'b' });
    expect(removeEnvFile(file)).toBe(true);
    expect(fs.existsSync(file)).toBe(false);
  });

  it('returns true and stays silent when the file is already gone', () => {
    const file = writeEnvFile(dir, 'scan-0', { A: 'b' });
    removeEnvFile(file);
    expect(removeEnvFile(file)).toBe(true);
  });

  // `force: true` on fs.rmSync only swallows ENOENT. A directory (EISDIR), a
  // permission error, or a locked file would all still throw - and this is called from
  // a caller's `finally` block after a scan, where a thrown delete error would replace
  // the real scan failure while the credentials file stays on disk. It must never
  // throw; it must instead report the failure so it is not silent.
  it('does not throw when the path is a directory, and reports the failure instead', () => {
    const sub = path.join(dir, 'sub');
    fs.mkdirSync(sub);
    const warnings: string[] = [];

    let result: boolean | undefined;
    expect(() => {
      result = removeEnvFile(sub, (message) => warnings.push(message));
    }).not.toThrow();

    expect(result).toBe(false);
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toMatch(/failed to remove/i);
    expect(fs.existsSync(sub)).toBe(true);
  });

  it('does not throw when given a non-string path', () => {
    let result: boolean | undefined;
    expect(() => {
      result = removeEnvFile(undefined as unknown as string);
    }).not.toThrow();
    expect(result).toBe(false);
  });
});
