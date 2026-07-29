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
});
