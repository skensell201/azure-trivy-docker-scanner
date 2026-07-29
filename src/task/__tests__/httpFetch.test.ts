import * as http from 'http';
import { AddressInfo } from 'net';
import { httpFetch } from '../httpFetch';

describe('httpFetch', () => {
  let server: http.Server;
  let base: string;
  let seenAuth: string | undefined;

  beforeAll((done) => {
    server = http.createServer((request, response) => {
      seenAuth = request.headers.authorization;
      if (request.url?.includes('missing')) {
        response.writeHead(404).end('nope');
        return;
      }
      response.writeHead(200, { 'content-type': 'application/json' }).end('{"value":[1,2]}');
    });
    server.listen(0, '127.0.0.1', () => {
      base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
      done();
    });
  });

  afterAll((done) => {
    server.close(() => done());
  });

  it('returns ok with the body for a 200 response', async () => {
    const response = await httpFetch(`${base}/doc`, { headers: {} });
    expect(response.ok).toBe(true);
    expect(response.status).toBe(200);
    await expect(response.text()).resolves.toBe('{"value":[1,2]}');
  });

  it('sends the authorization header', async () => {
    await httpFetch(`${base}/doc`, { headers: { Authorization: 'Bearer tok' } });
    expect(seenAuth).toBe('Bearer tok');
  });

  it('reports a non-ok status without throwing', async () => {
    const response = await httpFetch(`${base}/missing`, { headers: {} });
    expect(response).toMatchObject({ ok: false, status: 404 });
  });

  it('rejects when the host refuses the connection', async () => {
    await expect(httpFetch('http://127.0.0.1:1/doc', { headers: {} })).rejects.toThrow();
  });
});
