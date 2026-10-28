import {
  AUTH_EVENT_SCHEMA,
  acquireToken,
} from '../src/auth.js';
import fs from 'fs/promises';
import net from 'net';
import os from 'os';
import path from 'path';

const CALLBACK_ORIGIN = 'http://localhost:9898';
const LOCK_FILE = path.join(os.tmpdir(), 'da-auth-helper-integration-9898.lock');
let lockHandle;

async function acquireIntegrationLock() {
  const deadline = Date.now() + 15_000;
  while (Date.now() < deadline) {
    try {
      lockHandle = await fs.open(LOCK_FILE, 'wx', 0o600);
      await lockHandle.writeFile(`${process.pid}\n`);
      return;
    } catch (error) {
      if (error?.code !== 'EEXIST') throw error;
      try {
        const stats = await fs.stat(LOCK_FILE);
        if (Date.now() - stats.mtimeMs > 30_000) await fs.unlink(LOCK_FILE);
      } catch (statError) {
        if (statError?.code !== 'ENOENT') throw statError;
      }
      await new Promise((resolve) => setTimeout(resolve, 50 + Math.floor(Math.random() * 50)));
    }
  }
  throw new Error('Timed out waiting for the callback integration-test lock.');
}

function form(params) {
  return {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(params),
  };
}

async function loopbackBindError(host) {
  const server = net.createServer();
  try {
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(9898, host, resolve);
    });
    return null;
  } catch (error) {
    return error?.code;
  } finally {
    await new Promise((resolve) => {
      if (!server.listening) resolve();
      else server.close(resolve);
    });
  }
}

describe('real localhost callback lifecycle', () => {
  beforeAll(async () => {
    await acquireIntegrationLock();
  });

  afterAll(async () => {
    await lockHandle?.close();
    await fs.unlink(LOCK_FILE).catch(() => {});
  });

  test('binds, rejects the wrong state, accepts a POST candidate, and releases the port', async () => {
    const events = [];
    let callbackHeaders;

    const result = await acquireToken({
      openBrowser: false,
      timeoutMs: 5000,
      async onEvent(event) {
        events.push(event);
        if (event.event !== 'authorization_url') return;

        const callback = await fetch(`${CALLBACK_ORIGIN}/callback`, {
          redirect: 'manual',
        });
        callbackHeaders = callback.headers;
        const html = await callback.text();
        expect(html).toContain("method: 'POST'");

        expect(['EADDRINUSE', 'EAFNOSUPPORT', 'EADDRNOTAVAIL'])
          .toContain(await loopbackBindError('::1'));
        expect(await loopbackBindError('127.0.0.1')).toBe('EADDRINUSE');

        const rejected = await fetch(`${CALLBACK_ORIGIN}/token`, form({
          access_token: 'IGNORED_CANDIDATE',
          state: 'wrong-state',
        }));
        expect(rejected.status).toBe(403);

        const state = new URL(event.url).searchParams.get('state');
        const accepted = await fetch(`${CALLBACK_ORIGIN}/token`, form({
          access_token: 'INTEGRATION_CANDIDATE',
          expires_in: '3600',
          state,
        }));
        expect(accepted.status).toBe(204);
      },
    });

    expect(result).toMatchObject({
      token: 'INTEGRATION_CANDIDATE',
      tokenAcquired: true,
      persisted: false,
    });
    expect(callbackHeaders.get('cache-control')).toBe('no-store');
    expect(callbackHeaders.get('content-security-policy')).toContain("default-src 'none'");
    expect(events).toContainEqual(expect.objectContaining({
      schema: AUTH_EVENT_SCHEMA,
      event: 'callback_rejected',
      code: 'CALLBACK_STATE_MISMATCH',
    }));
    expect(JSON.stringify(events)).not.toContain('INTEGRATION_CANDIDATE');
    expect(JSON.stringify(events)).not.toContain('IGNORED_CANDIDATE');

    // A second attempt can bind immediately, proving the first listener was released.
    const controller = new AbortController();
    await expect(acquireToken({
      openBrowser: false,
      timeoutMs: 5000,
      signal: controller.signal,
      onEvent(event) {
        if (event.event === 'authorization_url') controller.abort();
      },
    })).rejects.toMatchObject({ code: 'AUTH_CANCELLED' });
  }, 15_000);
});
