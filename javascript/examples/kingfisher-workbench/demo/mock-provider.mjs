// Pure loopback synthetic provider. Importable so callers await readiness, keep
// it alive through the browser action, and close it only after native cleanup.
import { createServer } from 'node:http';
import { isCliEntrypoint } from '../src/safety.mjs';

export const TOKEN = 'acme_demo_a9B2c7D4e1F8g3H6';
export const RETIRED_TOKEN = 'acme_demo_Zz9Yy8Xx7Ww6Vv5U';
export const USERNAME = 'user_a9B2c7D4';
export async function startMockProvider({ port = 0 } = {}) {
  const state = { active: true, validationRequests: 0, revokeRequests: 0 };
  const server = createServer((request, response) => {
    const authorized = request.headers.authorization === `Bearer ${TOKEN}` && request.headers['x-user'] === USERNAME;
    if (request.method === 'GET' && request.url === '/identity') {
      state.validationRequests++;
      const authenticated = authorized && state.active;
      response.writeHead(authenticated ? 200 : 401, { 'Content-Type': 'application/json' });
      response.end(JSON.stringify({ authenticated }));
      return;
    }
    if (request.method === 'POST' && request.url === '/revoke') {
      state.revokeRequests++;
      if (!authorized || !state.active) { response.writeHead(401); response.end(); return; }
      state.active = false;
      response.writeHead(204); response.end();
      return;
    }
    response.writeHead(404); response.end();
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', resolve);
  });
  return {
    url: `http://127.0.0.1:${server.address().port}`, state,
    async close() {
      const stopped = new Promise((resolve) => server.close(resolve));
      server.closeAllConnections();
      await stopped;
    },
  };
}
if (isCliEntrypoint(import.meta.url)) {
  const mock = await startMockProvider();
  console.log(`[mock] ${mock.url} · synthetic token only`);
  const stop = async () => { await mock.close(); };
  process.once('SIGINT', stop);
  process.once('SIGTERM', stop);
}
