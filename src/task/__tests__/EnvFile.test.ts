import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
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

  // fs.writeFileSync only applies its `mode` option when it creates a new file: on an
  // existing path, opening with O_TRUNC leaves the current permission bits untouched.
  // So if anything had widened the file's mode between calls, a second writeEnvFile
  // call would silently keep that wider mode unless something re-asserts 0600 every
  // time. This proves the explicit chmodSync in the implementation is load-bearing,
  // not a redundant restatement of the `mode` passed to writeFileSync.
  it('restores 0600 on a second call even if the file was widened in between', () => {
    const file = writeEnvFile(dir, 'scan-0', { A: 'first' });
    fs.chmodSync(file, 0o644);
    writeEnvFile(dir, 'scan-0', { A: 'second' });
    expect(fs.statSync(file).mode & 0o777).toBe(0o600);
  });
});
