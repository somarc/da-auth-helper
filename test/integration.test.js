import {
  AUTH_EVENT_SCHEMA,
  acquireToken,
} from '../src/auth.js';

const CALLBACK_ORIGIN = 'http://localhost:9898';

function form(params) {
  return {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(params),
  };
}

describe('real localhost callback lifecycle', () => {
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
