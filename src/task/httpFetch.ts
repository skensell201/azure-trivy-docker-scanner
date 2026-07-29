import * as http from 'http';
import * as https from 'https';
import { URL } from 'url';
import { FetchLike } from './ConfigClient';

export const httpFetch: FetchLike = (url, init) =>
  new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const transport = parsed.protocol === 'http:' ? http : https;

    const request = transport.request(
      parsed,
      { method: 'GET', headers: init.headers },
      (response) => {
        let body = '';
        response.setEncoding('utf8');
        response.on('data', (chunk: string) => {
          body += chunk;
        });
        response.on('end', () => {
          const status = response.statusCode ?? 0;
          resolve({ ok: status >= 200 && status < 300, status, text: async () => body });
        });
      },
    );

    request.on('error', reject);
    request.end();
  });
