import { selectOsCaBundlePath } from '../trustSource';

describe('selectOsCaBundlePath', () => {
  it('returns the first candidate the predicate reports as existing', () => {
    const exists = (candidatePath: string) => candidatePath === '/etc/pki/tls/certs/ca-bundle.crt';
    const result = selectOsCaBundlePath(
      ['/etc/ssl/certs/ca-certificates.crt', '/etc/pki/tls/certs/ca-bundle.crt', '/etc/ssl/ca-bundle.pem'],
      exists,
    );
    expect(result).toBe('/etc/pki/tls/certs/ca-bundle.crt');
  });

  it('respects candidate order when more than one exists', () => {
    const exists = () => true;
    const result = selectOsCaBundlePath(
      ['/etc/ssl/certs/ca-certificates.crt', '/etc/pki/tls/certs/ca-bundle.crt'],
      exists,
    );
    expect(result).toBe('/etc/ssl/certs/ca-certificates.crt');
  });

  it('returns undefined when nothing exists (e.g. a Windows or macOS agent)', () => {
    const exists = () => false;
    const result = selectOsCaBundlePath(
      ['/etc/ssl/certs/ca-certificates.crt', '/etc/pki/tls/certs/ca-bundle.crt', '/etc/ssl/ca-bundle.pem'],
      exists,
    );
    expect(result).toBeUndefined();
  });

  it('returns undefined for an empty candidate list', () => {
    expect(selectOsCaBundlePath([], () => true)).toBeUndefined();
  });
});
