import { ConfigClient, ConfigUnavailableError } from '../ConfigClient';

const okResponse = (value: unknown) => ({
  ok: true,
  status: 200,
  text: async () => JSON.stringify({ id: 'runners', value }),
});

describe('ConfigClient', () => {
  it('requests the document from the extension data collection', async () => {
    const fetchMock = jest.fn().mockResolvedValue(okResponse([{ alias: 'baseline' }]));
    const client = new ConfigClient({
      collectionUri: 'https://ado.corp/DefaultCollection/',
      publisher: 'iksoftware',
      extensionId: 'trivy-docker-scanner',
      auth: { mode: 'bearer', token: 'tok' },
      fetch: fetchMock,
    });

    await client.readDocument('runners');

    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe(
      'https://ado.corp/DefaultCollection/_apis/ExtensionManagement/InstalledExtensions/iksoftware/trivy-docker-scanner/Data/Scopes/Default/Current/Collections/%24settings/Documents/runners?api-version=3.2-preview.1',
    );
    expect(init.headers.Authorization).toBe('Bearer tok');
  });

  it('sends basic auth when configured for a personal access token', async () => {
    const fetchMock = jest.fn().mockResolvedValue(okResponse([]));
    const client = new ConfigClient({
      collectionUri: 'https://ado.corp/DefaultCollection',
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
      collectionUri: 'https://ado.corp/DefaultCollection',
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
      collectionUri: 'https://ado.corp/DefaultCollection',
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
      collectionUri: 'https://ado.corp/DefaultCollection',
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
      collectionUri: 'https://ado.corp/DefaultCollection',
      publisher: 'iksoftware',
      extensionId: 'trivy-docker-scanner',
      auth: { mode: 'bearer', token: 'tok' },
      fetch: fetchMock,
    });

    await client.readDocument('runners').catch((error: Error) => {
      expect(error).toBeInstanceOf(ConfigUnavailableError);
      expect(error.message).toContain('x'.repeat(200));
      expect(error.message).not.toContain('x'.repeat(201));
    });
  });

  it('rejects a 200 response whose document has no value field, rather than treating it as unconfigured', async () => {
    const fetchMock = jest
      .fn()
      .mockResolvedValue({ ok: true, status: 200, text: async () => JSON.stringify({ id: 'runners' }) });
    const client = new ConfigClient({
      collectionUri: 'https://ado.corp/DefaultCollection',
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
      collectionUri: 'https://ado.corp/DefaultCollection',
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
      collectionUri: 'https://ado.corp/DefaultCollection',
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
      collectionUri: 'https://ado.corp/DefaultCollection',
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
      collectionUri: 'https://ado.corp/DefaultCollection',
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
      collectionUri: 'https://ado.corp/DefaultCollection',
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
      collectionUri: 'ado.corp/DefaultCollection',
      publisher: 'iksoftware',
      extensionId: 'trivy-docker-scanner',
      auth: { mode: 'bearer', token: 'tok' },
      fetch: fetchMock,
    });

    await expect(client.readDocument('runners')).rejects.toThrow(ConfigUnavailableError);
    await expect(client.readDocument('runners')).rejects.toThrow(/System\.CollectionUri/);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
