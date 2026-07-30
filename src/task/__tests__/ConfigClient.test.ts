import { ConfigClient, ConfigUnavailableError } from '../ConfigClient';

const okResponse = (value: unknown) => ({
  ok: true,
  status: 200,
  text: async () => JSON.stringify({ id: 'runners', value }),
});

/**
 * Awaits a promise expected to reject and returns the rejection reason. Unlike
 * a bare `.catch(cb)`, this fails the test (via the thrown Error) if the
 * promise resolves instead of rejecting, so assertions inside the caller
 * cannot be silently skipped.
 */
async function rejection(promise: Promise<unknown>): Promise<Error> {
  try {
    await promise;
  } catch (error) {
    return error as Error;
  }
  throw new Error('expected the promise to reject, but it resolved');
}

describe('ConfigClient', () => {
  it('requests the document from the extension data collection', async () => {
    const fetchMock = jest.fn().mockResolvedValue(okResponse([{ alias: 'baseline' }]));
    const client = new ConfigClient({
      collectionUri: 'https://dev.example.com/DefaultCollection/',
      publisher: 'iksoftware',
      extensionId: 'trivy-docker-scanner',
      auth: { mode: 'bearer', token: 'tok' },
      fetch: fetchMock,
    });

    await client.readDocument('runners');

    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe(
      'https://dev.example.com/DefaultCollection/_apis/ExtensionManagement/InstalledExtensions/iksoftware/trivy-docker-scanner/Data/Scopes/Default/Current/Collections/%24settings/Documents/runners?api-version=3.2-preview.1',
    );
    expect(init.headers.Authorization).toBe('Bearer tok');
  });

  it('sends basic auth when configured for a personal access token', async () => {
    const fetchMock = jest.fn().mockResolvedValue(okResponse([]));
    const client = new ConfigClient({
      collectionUri: 'https://dev.example.com/DefaultCollection',
      publisher: 'iksoftware',
      extensionId: 'trivy-docker-scanner',
      auth: { mode: 'pat', token: 'mypat' },
      fetch: fetchMock,
    });

    await client.readDocument('runners');

    const expected = `Basic ${Buffer.from(':mypat').toString('base64')}`;
    expect(fetchMock.mock.calls[0][1].headers.Authorization).toBe(expected);
  });

  it('returns the value field of the document', async () => {
    const fetchMock = jest.fn().mockResolvedValue(okResponse([{ alias: 'baseline' }]));
    const client = new ConfigClient({
      collectionUri: 'https://dev.example.com/DefaultCollection',
      publisher: 'iksoftware',
      extensionId: 'trivy-docker-scanner',
      auth: { mode: 'bearer', token: 'tok' },
      fetch: fetchMock,
    });

    await expect(client.readDocument('runners')).resolves.toEqual([{ alias: 'baseline' }]);
  });

  it('returns undefined when the document does not exist yet', async () => {
    // 404 is the ONLY path that resolves to undefined: it means the
    // administrator has not saved this document yet. Contrast with the
    // "no value field" test below, which is a corrupted 200 and must throw
    // rather than be reported to the administrator as "not configured".
    const fetchMock = jest.fn().mockResolvedValue({ ok: false, status: 404, text: async () => '' });
    const client = new ConfigClient({
      collectionUri: 'https://dev.example.com/DefaultCollection',
      publisher: 'iksoftware',
      extensionId: 'trivy-docker-scanner',
      auth: { mode: 'bearer', token: 'tok' },
      fetch: fetchMock,
    });

    await expect(client.readDocument('runners')).resolves.toBeUndefined();
  });

  it('rejects a 200 response that is not valid JSON, including a body preview', async () => {
    // On-premises, a 200 with an HTML sign-in or error page is the realistic
    // cause of this, not a truncated network response. The reader needs to
    // see enough of the body to recognize that.
    const html = '<!doctype html><html><body>Sign in with your corporate account to continue...</body></html>';
    const fetchMock = jest.fn().mockResolvedValue({ ok: true, status: 200, text: async () => html });
    const client = new ConfigClient({
      collectionUri: 'https://dev.example.com/DefaultCollection',
      publisher: 'iksoftware',
      extensionId: 'trivy-docker-scanner',
      auth: { mode: 'bearer', token: 'tok' },
      fetch: fetchMock,
    });

    await expect(client.readDocument('runners')).rejects.toThrow(ConfigUnavailableError);
    await expect(client.readDocument('runners')).rejects.toThrow(/runners/);
    await expect(client.readDocument('runners')).rejects.toThrow(/Sign in with your corporate account/);
  });

  it('truncates the body preview of a non-JSON response to 200 characters', async () => {
    const longBody = 'x'.repeat(500);
    const fetchMock = jest.fn().mockResolvedValue({ ok: true, status: 200, text: async () => longBody });
    const client = new ConfigClient({
      collectionUri: 'https://dev.example.com/DefaultCollection',
      publisher: 'iksoftware',
      extensionId: 'trivy-docker-scanner',
      auth: { mode: 'bearer', token: 'tok' },
      fetch: fetchMock,
    });

    const error = await rejection(client.readDocument('runners'));

    expect(error).toBeInstanceOf(ConfigUnavailableError);
    expect(error.message).toContain('x'.repeat(200));
    expect(error.message).not.toContain('x'.repeat(201));
  });

  it('does not split a surrogate pair when truncating the body preview at the 200-character boundary', async () => {
    // 199 ASCII chars put the boundary exactly inside the two-code-unit emoji
    // that follows, if truncation is done by UTF-16 code unit rather than by
    // code point.
    const body = `${'x'.repeat(199)}\u{1F600}${'y'.repeat(300)}`;
    const fetchMock = jest.fn().mockResolvedValue({ ok: true, status: 200, text: async () => body });
    const client = new ConfigClient({
      collectionUri: 'https://dev.example.com/DefaultCollection',
      publisher: 'iksoftware',
      extensionId: 'trivy-docker-scanner',
      auth: { mode: 'bearer', token: 'tok' },
      fetch: fetchMock,
    });

    const error = await rejection(client.readDocument('runners'));

    expect(error.message).toContain('\u{1F600}');
  });

  it('sanitizes control characters and neutralizes a forged ##vso logging command in the body preview', async () => {
    const malicious = 'oops\n##vso[task.complete result=Succeeded]\nmore binary';
    const fetchMock = jest.fn().mockResolvedValue({ ok: true, status: 200, text: async () => malicious });
    const client = new ConfigClient({
      collectionUri: 'https://dev.example.com/DefaultCollection',
      publisher: 'iksoftware',
      extensionId: 'trivy-docker-scanner',
      auth: { mode: 'bearer', token: 'tok' },
      fetch: fetchMock,
    });

    const error = await rejection(client.readDocument('runners'));

    expect(error).toBeInstanceOf(ConfigUnavailableError);
    expect(error.message).toContain('oops');
    expect(error.message).not.toContain('##vso[');
    expect(error.message).not.toMatch(/[\n\r]/);
  });

  it('rejects a 200 response whose document has no value field, rather than treating it as unconfigured', async () => {
    const fetchMock = jest
      .fn()
      .mockResolvedValue({ ok: true, status: 200, text: async () => JSON.stringify({ id: 'runners' }) });
    const client = new ConfigClient({
      collectionUri: 'https://dev.example.com/DefaultCollection',
      publisher: 'iksoftware',
      extensionId: 'trivy-docker-scanner',
      auth: { mode: 'bearer', token: 'tok' },
      fetch: fetchMock,
    });

    await expect(client.readDocument('runners')).rejects.toThrow(ConfigUnavailableError);
    await expect(client.readDocument('runners')).rejects.toThrow(/runners/);
  });

  it('explains an authorization failure in terms the pipeline author can act on', async () => {
    const fetchMock = jest.fn().mockResolvedValue({ ok: false, status: 403, text: async () => 'no' });
    const client = new ConfigClient({
      collectionUri: 'https://dev.example.com/DefaultCollection',
      publisher: 'iksoftware',
      extensionId: 'trivy-docker-scanner',
      auth: { mode: 'bearer', token: 'tok' },
      fetch: fetchMock,
    });

    await expect(client.readDocument('runners')).rejects.toThrow(ConfigUnavailableError);
    await expect(client.readDocument('runners')).rejects.toThrow(/Allow scripts to access the OAuth token|configConnection/);
  });

  it('surfaces a transport failure as ConfigUnavailableError', async () => {
    const fetchMock = jest.fn().mockRejectedValue(new Error('ECONNREFUSED'));
    const client = new ConfigClient({
      collectionUri: 'https://dev.example.com/DefaultCollection',
      publisher: 'iksoftware',
      extensionId: 'trivy-docker-scanner',
      auth: { mode: 'bearer', token: 'tok' },
      fetch: fetchMock,
    });

    await expect(client.readDocument('runners')).rejects.toThrow(/ECONNREFUSED/);
  });

  // Pinning tests below lock down behavior that already holds today, so a
  // future change cannot silently regress it or the hazard it documents.

  it('never puts the auth token in a transport-failure error message', async () => {
    const fetchMock = jest.fn().mockRejectedValue(new Error('ECONNREFUSED'));
    const client = new ConfigClient({
      collectionUri: 'https://dev.example.com/DefaultCollection',
      publisher: 'iksoftware',
      extensionId: 'trivy-docker-scanner',
      auth: { mode: 'pat', token: 'super-secret-pat' },
      fetch: fetchMock,
    });

    await expect(client.readDocument('runners')).rejects.not.toThrow(/super-secret-pat/);
  });

  it('never puts the auth token in an HTTP-failure error message', async () => {
    const fetchMock = jest.fn().mockResolvedValue({ ok: false, status: 403, text: async () => 'no' });
    const client = new ConfigClient({
      collectionUri: 'https://dev.example.com/DefaultCollection',
      publisher: 'iksoftware',
      extensionId: 'trivy-docker-scanner',
      auth: { mode: 'bearer', token: 'super-secret-token' },
      fetch: fetchMock,
    });

    await expect(client.readDocument('runners')).rejects.not.toThrow(/super-secret-token/);
  });

  it('encodes the document id before interpolating it into the URL', async () => {
    // Both current callers pass fixed literals ('runners', 'defaults'), so this
    // is not exploitable today, but the method takes a bare string: a future
    // caller passing an untrusted id must not be able to inject path segments
    // or query parameters into the request URL.
    const fetchMock = jest.fn().mockResolvedValue(okResponse([]));
    const client = new ConfigClient({
      collectionUri: 'https://dev.example.com/DefaultCollection',
      publisher: 'iksoftware',
      extensionId: 'trivy-docker-scanner',
      auth: { mode: 'bearer', token: 'tok' },
      fetch: fetchMock,
    });

    await client.readDocument('../other?x=1');

    const [url] = fetchMock.mock.calls[0];
    expect(url).toContain(`/Documents/${encodeURIComponent('../other?x=1')}?api-version=`);
    expect(url).not.toContain('/Documents/../other?x=1?api-version=');
  });

  it('rejects an empty collectionUri, naming System.CollectionUri as the setting to fix', async () => {
    const fetchMock = jest.fn();
    const client = new ConfigClient({
      collectionUri: '',
      publisher: 'iksoftware',
      extensionId: 'trivy-docker-scanner',
      auth: { mode: 'bearer', token: 'tok' },
      fetch: fetchMock,
    });

    await expect(client.readDocument('runners')).rejects.toThrow(ConfigUnavailableError);
    await expect(client.readDocument('runners')).rejects.toThrow(/System\.CollectionUri/);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('rejects a collectionUri without an http/https scheme', async () => {
    const fetchMock = jest.fn();
    const client = new ConfigClient({
      collectionUri: 'dev.example.com/DefaultCollection',
      publisher: 'iksoftware',
      extensionId: 'trivy-docker-scanner',
      auth: { mode: 'bearer', token: 'tok' },
      fetch: fetchMock,
    });

    await expect(client.readDocument('runners')).rejects.toThrow(ConfigUnavailableError);
    await expect(client.readDocument('runners')).rejects.toThrow(/System\.CollectionUri/);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('encodes publisher and extensionId before interpolating them into the URL', async () => {
    const fetchMock = jest.fn().mockResolvedValue(okResponse([]));
    const client = new ConfigClient({
      collectionUri: 'https://dev.example.com/DefaultCollection',
      publisher: 'ik software',
      extensionId: 'trivy/scanner',
      auth: { mode: 'bearer', token: 'tok' },
      fetch: fetchMock,
    });

    await client.readDocument('runners');

    const [url] = fetchMock.mock.calls[0];
    expect(url).toContain(
      `/InstalledExtensions/${encodeURIComponent('ik software')}/${encodeURIComponent('trivy/scanner')}/Data/`,
    );
  });

  it('does not leak collectionUri userinfo into a transport-failure message, but still sends it to fetch', async () => {
    const fetchMock = jest.fn().mockRejectedValue(new Error('ECONNREFUSED'));
    const client = new ConfigClient({
      collectionUri: 'https://user:s3cr3t@dev.example.com/DC',
      publisher: 'iksoftware',
      extensionId: 'trivy-docker-scanner',
      auth: { mode: 'bearer', token: 'tok' },
      fetch: fetchMock,
    });

    const error = await rejection(client.readDocument('runners'));

    expect(error).toBeInstanceOf(ConfigUnavailableError);
    expect(error.message).not.toContain('s3cr3t');
    expect(error.message).toContain('https://dev.example.com/DC');
    // The request itself still needs the credentials to reach the server;
    // only messages surfaced to the reader are redacted.
    const [url] = fetchMock.mock.calls[0];
    expect(url).toContain('user:s3cr3t@dev.example.com');
  });

  it('does not leak userinfo into the invalid-collectionUri message either', async () => {
    const client = new ConfigClient({
      collectionUri: 'ftp://user:s3cr3t@dev.example.com/DC',
      publisher: 'iksoftware',
      extensionId: 'trivy-docker-scanner',
      auth: { mode: 'bearer', token: 'tok' },
      fetch: jest.fn(),
    });

    const error = await rejection(client.readDocument('runners'));

    expect(error).toBeInstanceOf(ConfigUnavailableError);
    expect(error.message).toContain('System.CollectionUri');
    expect(error.message).not.toContain('s3cr3t');
  });

  it('logs which document was missing and at which URL when a 404 causes the undefined fallback', async () => {
    const fetchMock = jest.fn().mockResolvedValue({ ok: false, status: 404, text: async () => '' });
    const log = jest.fn();
    const client = new ConfigClient({
      collectionUri: 'https://dev.example.com/DefaultCollection',
      publisher: 'iksoftware',
      extensionId: 'trivy-docker-scanner',
      auth: { mode: 'bearer', token: 'tok' },
      fetch: fetchMock,
      log,
    });

    await expect(client.readDocument('runners')).resolves.toBeUndefined();

    expect(log).toHaveBeenCalledTimes(1);
    const [message] = log.mock.calls[0];
    expect(message).toContain('runners');
    expect(message).toContain(
      'https://dev.example.com/DefaultCollection/_apis/ExtensionManagement/InstalledExtensions/iksoftware/trivy-docker-scanner',
    );
  });

  it('does not require a log callback', async () => {
    // The callback is optional: callers that do not care about diagnosing a
    // missing document (or have not been updated yet) must not crash.
    const fetchMock = jest.fn().mockResolvedValue({ ok: false, status: 404, text: async () => '' });
    const client = new ConfigClient({
      collectionUri: 'https://dev.example.com/DefaultCollection',
      publisher: 'iksoftware',
      extensionId: 'trivy-docker-scanner',
      auth: { mode: 'bearer', token: 'tok' },
      fetch: fetchMock,
    });

    await expect(client.readDocument('runners')).resolves.toBeUndefined();
  });

  it('resolves to null (not undefined) when the document value field is explicitly null', async () => {
    // JSON.parse('{"value":null}').value is `null`, not `undefined`; the
    // return type says so explicitly rather than silently widening it away.
    const fetchMock = jest
      .fn()
      .mockResolvedValue({ ok: true, status: 200, text: async () => JSON.stringify({ id: 'runners', value: null }) });
    const client = new ConfigClient({
      collectionUri: 'https://dev.example.com/DefaultCollection',
      publisher: 'iksoftware',
      extensionId: 'trivy-docker-scanner',
      auth: { mode: 'bearer', token: 'tok' },
      fetch: fetchMock,
    });

    await expect(client.readDocument('runners')).resolves.toBeNull();
  });

  it('wraps a rejecting response.text() as ConfigUnavailableError, not a raw error', async () => {
    const fetchMock = jest
      .fn()
      .mockResolvedValue({ ok: true, status: 200, text: () => Promise.reject(new Error('stream closed')) });
    const client = new ConfigClient({
      collectionUri: 'https://dev.example.com/DefaultCollection',
      publisher: 'iksoftware',
      extensionId: 'trivy-docker-scanner',
      auth: { mode: 'bearer', token: 'tok' },
      fetch: fetchMock,
    });

    const error = await rejection(client.readDocument('runners'));

    expect(error).toBeInstanceOf(ConfigUnavailableError);
    expect(error.message).toContain('stream closed');
  });
});
