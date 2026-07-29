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
});
