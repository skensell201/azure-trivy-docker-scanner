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

  it('interpolates the document id into the URL without encoding it', async () => {
    // Both current callers pass fixed literals ('runners', 'defaults'), so this
    // is not exploitable today, but the method takes a bare string: a future
    // caller passing an untrusted id could inject path segments or query
    // parameters. This test pins the current passthrough so that hazard is
    // visible rather than silent.
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
    expect(url).toContain('/Documents/../other?x=1?api-version=');
  });

  it('builds a hostless URL when collectionUri is empty, rather than rejecting it up front', async () => {
    // There is no validation of collectionUri: an empty (or schemeless) value
    // silently produces a URL with no host. A real fetch implementation would
    // reject such a URL, but the resulting ConfigUnavailableError would only
    // report a generic connection failure, not "collectionUri is not set".
    const fetchMock = jest.fn().mockResolvedValue(okResponse([]));
    const client = new ConfigClient({
      collectionUri: '',
      publisher: 'iksoftware',
      extensionId: 'trivy-docker-scanner',
      auth: { mode: 'bearer', token: 'tok' },
      fetch: fetchMock,
    });

    await client.readDocument('runners');

    const [url] = fetchMock.mock.calls[0];
    expect(url).toBe(
      '/_apis/ExtensionManagement/InstalledExtensions/iksoftware/trivy-docker-scanner/Data/Scopes/Default/Current/Collections/%24settings/Documents/runners?api-version=3.2-preview.1',
    );
  });
});
