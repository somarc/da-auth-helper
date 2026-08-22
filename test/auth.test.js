import { EventEmitter } from 'events';
import { jest } from '@jest/globals';

// ─── Mock credential storage ─────────────────────────────────────────────────

const TOKEN_FILE = '/mock-home/.aem/da-token.json';
const mockLoadStoredToken = jest.fn();
const mockStoreToken = jest.fn();
const mockClearStoredToken = jest.fn();
jest.unstable_mockModule('../src/storage.js', () => ({
  TOKEN_FILE,
  loadStoredToken: mockLoadStoredToken,
  storeToken: mockStoreToken,
  clearStoredToken: mockClearStoredToken,
}));

// ─── Mock open ────────────────────────────────────────────────────────────────

const mockOpen = jest.fn();
jest.unstable_mockModule('open', () => ({ default: mockOpen }));

// ─── Mock http ────────────────────────────────────────────────────────────────

let capturedRequestHandler;
let currentServer;
let listenError;

function makeServer() {
  const emitter = new EventEmitter();
  const server = {
    listening: false,
    listen: jest.fn((port, host, callback) => {
      queueMicrotask(() => {
        if (listenError) {
          emitter.emit('error', listenError);
          return;
        }
        server.listening = true;
        callback?.();
      });
      return server;
    }),
    close: jest.fn((callback) => {
      server.listening = false;
      callback?.();
      return server;
    }),
    closeAllConnections: jest.fn(),
    on: jest.fn((event, callback) => {
      emitter.on(event, callback);
      return server;
    }),
    once: jest.fn((event, callback) => {
      emitter.once(event, callback);
      return server;
    }),
    off: jest.fn((event, callback) => {
      emitter.off(event, callback);
      return server;
    }),
    emit: (...args) => emitter.emit(...args),
  };
  return server;
}

const mockHttpCreate = jest.fn((handler) => {
  capturedRequestHandler = handler;
  currentServer = makeServer();
  return currentServer;
});
jest.unstable_mockModule('http', () => ({ default: { createServer: mockHttpCreate } }));

// ─── Import SUT after mocks ───────────────────────────────────────────────────

const {
  AUTH_EVENT_SCHEMA,
  AuthError,
  acquireToken,
  clearStoredToken,
  getValidToken,
} = await import('../src/auth.js');

// ─── Helpers ──────────────────────────────────────────────────────────────────

function makeReq(pathname, {
  method = 'GET',
  headers = {},
  body = '',
} = {}) {
  const req = new EventEmitter();
  req.url = pathname;
  req.method = method;
  req.headers = headers;
  queueMicrotask(() => {
    if (body) req.emit('data', Buffer.from(body));
    req.emit('end');
  });
  return req;
}

function makeRes() {
  let resolveEnded;
  const ended = new Promise((resolve) => { resolveEnded = resolve; });
  return {
    statusCode: null,
    headers: {},
    headersSent: false,
    writableEnded: false,
    body: '',
    ended,
    writeHead: jest.fn(function writeHead(code, headers = {}) {
      this.statusCode = code;
      this.headers = headers;
      this.headersSent = true;
    }),
    end: jest.fn(function end(data = '') {
      this.body += data;
      this.writableEnded = true;
      resolveEnded();
    }),
  };
}

async function sendRequest(pathname, options) {
  const response = makeRes();
  capturedRequestHandler(makeReq(pathname, options), response);
  await response.ended;
  return response;
}

async function postCallback(params) {
  return sendRequest('/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(params).toString(),
  });
}

function stateFromUrl(url) {
  return new URL(url).searchParams.get('state');
}

function completeFromOpen(token = 'BROWSER_TOKEN', expiresIn = '3600') {
  mockOpen.mockImplementationOnce(async (authUrl) => {
    await postCallback({
      access_token: token,
      expires_in: String(expiresIn),
      state: stateFromUrl(authUrl),
    });
  });
}

function eventCollector({ completeWith, expiresIn = '3600', controller, callback } = {}) {
  const events = [];
  const onEvent = jest.fn(async (event) => {
    events.push(event);
    if (event.event !== 'authorization_url') return;
    if (callback) await callback(event, events);
    if (controller) controller.abort();
    if (completeWith) {
      await postCallback({
        access_token: completeWith,
        expires_in: String(expiresIn),
        state: stateFromUrl(event.url),
      });
    }
  });
  return { events, onEvent };
}

beforeEach(() => {
  jest.clearAllMocks();
  capturedRequestHandler = undefined;
  currentServer = undefined;
  listenError = undefined;
  mockLoadStoredToken.mockResolvedValue(null);
  mockStoreToken.mockResolvedValue(undefined);
  mockClearStoredToken.mockResolvedValue(undefined);
  mockOpen.mockResolvedValue(undefined);
});

describe('public compatibility surface', () => {
  test('exports the original functions and the versioned acquisition contract', () => {
    expect(typeof getValidToken).toBe('function');
    expect(typeof clearStoredToken).toBe('function');
    expect(typeof acquireToken).toBe('function');
    expect(AUTH_EVENT_SCHEMA).toBe('da-auth-helper.event.v1');
    expect(new AuthError('TEST', 'test')).toMatchObject({ code: 'TEST', retryable: false });
  });

  test('returns an override without touching cache, listener, events, or browser', async () => {
    const onEvent = jest.fn();
    await expect(getValidToken({ override: 'OVERRIDE', onEvent })).resolves.toBe('OVERRIDE');
    expect(mockLoadStoredToken).not.toHaveBeenCalled();
    expect(mockHttpCreate).not.toHaveBeenCalled();
    expect(mockOpen).not.toHaveBeenCalled();
    expect(onEvent).not.toHaveBeenCalled();
  });

  test('returns a valid cached token without starting an attempt', async () => {
    mockLoadStoredToken.mockResolvedValue({
      access_token: 'CACHED',
      expires_at: Date.now() + 61_000,
    });

    await expect(getValidToken()).resolves.toBe('CACHED');
    expect(mockHttpCreate).not.toHaveBeenCalled();
    expect(mockOpen).not.toHaveBeenCalled();
  });

  test('treats the exact 60-second skew boundary as expired', async () => {
    const now = Date.now();
    jest.spyOn(Date, 'now').mockReturnValue(now);
    mockLoadStoredToken.mockResolvedValue({ access_token: 'OLD', expires_at: now + 60_000 });
    completeFromOpen('FRESH');

    await expect(getValidToken({ log: () => {} })).resolves.toBe('FRESH');
    expect(mockOpen).toHaveBeenCalledTimes(1);
    Date.now.mockRestore();
  });

  test('treats a legacy cache entry without expires_at as expired', async () => {
    mockLoadStoredToken.mockResolvedValue({ access_token: 'LEGACY' });
    completeFromOpen('FRESH');

    await expect(getValidToken({ log: () => {} })).resolves.toBe('FRESH');
  });
});

describe('caller-owned acquireToken contract', () => {
  test('binds before emitting one exact no-open authorization event and never touches storage', async () => {
    const { events, onEvent } = eventCollector({ completeWith: 'CALLER_OWNED' });

    const result = await acquireToken({ openBrowser: false, onEvent });

    expect(currentServer.listen).toHaveBeenCalledWith(9898, 'localhost', expect.any(Function));
    expect(mockOpen).not.toHaveBeenCalled();
    expect(mockLoadStoredToken).not.toHaveBeenCalled();
    expect(mockStoreToken).not.toHaveBeenCalled();
    expect(mockClearStoredToken).not.toHaveBeenCalled();
    expect(result).toMatchObject({
      token: 'CALLER_OWNED',
      tokenAcquired: true,
      persisted: false,
      reauthenticationRequested: false,
    });

    const authorization = events[0];
    expect(Object.keys(authorization).sort()).toEqual([
      'callbackPort',
      'deadlineAt',
      'event',
      'reauthenticationRequested',
      'redirectUri',
      'schema',
      'url',
    ]);
    expect(authorization).toMatchObject({
      schema: AUTH_EVENT_SCHEMA,
      event: 'authorization_url',
      callbackPort: 9898,
      redirectUri: 'http://localhost:9898/callback',
      reauthenticationRequested: false,
    });
    expect(stateFromUrl(authorization.url)).toMatch(/^[a-f0-9]{32}$/);
    expect(events.at(-1)).toMatchObject({
      schema: AUTH_EVENT_SCHEMA,
      event: 'completed',
      tokenAcquired: true,
      persisted: false,
    });
    expect(JSON.stringify(events)).not.toContain('CALLER_OWNED');
  });

  test('adds prompt=login only for explicit reauthentication', async () => {
    const forced = eventCollector({ completeWith: 'FORCED' });
    await acquireToken({ reauthenticate: true, openBrowser: false, onEvent: forced.onEvent });
    expect(new URL(forced.events[0].url).searchParams.get('prompt')).toBe('login');

    const ordinary = eventCollector({ completeWith: 'ORDINARY' });
    await acquireToken({ openBrowser: false, onEvent: ordinary.onEvent });
    expect(new URL(ordinary.events[0].url).searchParams.has('prompt')).toBe(false);
  });

  test('reauthenticating getValidToken bypasses a valid cache and atomically reaches persistence', async () => {
    mockLoadStoredToken.mockResolvedValue({
      access_token: 'CACHED',
      expires_at: Date.now() + 60 * 60 * 1000,
    });
    completeFromOpen('FRESH');

    await expect(getValidToken({ reauthenticate: true, log: () => {} })).resolves.toBe('FRESH');

    expect(mockLoadStoredToken).not.toHaveBeenCalled();
    expect(new URL(mockOpen.mock.calls[0][0]).searchParams.get('prompt')).toBe('login');
    expect(mockStoreToken).toHaveBeenCalledWith(
      expect.objectContaining({ access_token: 'FRESH' }),
    );
  });

  test('default browser acquisition does not add prompt=login', async () => {
    completeFromOpen('DEFAULT');
    await getValidToken({ log: () => {} });
    expect(new URL(mockOpen.mock.calls[0][0]).searchParams.has('prompt')).toBe(false);
  });

  test('interprets ordinary expires_in as seconds', async () => {
    const before = Date.now();
    const { events, onEvent } = eventCollector({ completeWith: 'TOKEN', expiresIn: '3600' });
    const result = await acquireToken({ openBrowser: false, onEvent });
    expect(result.expirySource).toBe('ims-expires-in');
    expect(result.expiresAt).toBeGreaterThanOrEqual(before + 3_600_000);
    expect(events.at(-1).expiresAt).toBe(result.expiresAt);
  });

  test('interprets the observed IMS 86400000 expires_in value as milliseconds', async () => {
    const before = Date.now();
    const { onEvent } = eventCollector({ completeWith: 'TOKEN', expiresIn: '86400000' });
    const result = await acquireToken({ openBrowser: false, onEvent });
    expect(result.expiresAt).toBeGreaterThanOrEqual(before + 86_400_000);
    expect(result.expiresAt).toBeLessThan(before + 86_400_000 + 1000);
  });

  test('prefers a bounded JWT exp claim over expires_in', async () => {
    const expiresAt = Date.now() + 10 * 60 * 1000;
    const payload = Buffer.from(JSON.stringify({ exp: Math.floor(expiresAt / 1000) }))
      .toString('base64url');
    const token = `header.${payload}.signature`;
    const { onEvent } = eventCollector({ completeWith: token, expiresIn: '3600' });
    const result = await acquireToken({ openBrowser: false, onEvent });
    expect(result.expirySource).toBe('jwt-exp');
    expect(result.expiresAt).toBe(Math.floor(expiresAt / 1000) * 1000);
  });

  test('does not invent expiry metadata from malformed values', async () => {
    const { onEvent } = eventCollector({ completeWith: 'TOKEN', expiresIn: 'not-a-number' });
    await expect(acquireToken({ openBrowser: false, onEvent })).resolves.toMatchObject({
      expiresAt: null,
      expirySource: null,
    });
  });
});

describe('callback security and browser truth', () => {
  test('uses a state-bound POST body, rejects a mismatch, and keeps listening for the genuine callback', async () => {
    let rejectedResponse;
    const { events, onEvent } = eventCollector({
      callback: async (event) => {
        rejectedResponse = await postCallback({
          access_token: 'ATTACKER',
          state: 'wrong-state',
        });
        await new Promise((resolve) => setImmediate(resolve));
        await postCallback({
          access_token: 'GENUINE',
          expires_in: '3600',
          state: stateFromUrl(event.url),
        });
      },
    });

    const result = await acquireToken({ openBrowser: false, onEvent });

    expect(rejectedResponse.statusCode).toBe(403);
    expect(result.token).toBe('GENUINE');
    expect(events).toContainEqual(expect.objectContaining({
      event: 'callback_rejected',
      code: 'CALLBACK_STATE_MISMATCH',
    }));
    expect(JSON.stringify(events)).not.toContain('ATTACKER');
    expect(JSON.stringify(events)).not.toContain('GENUINE');
  });

  test('rejects GET /token so a bearer is never accepted from a request URL', async () => {
    const controller = new AbortController();
    let response;
    const { onEvent } = eventCollector({
      controller,
      callback: async (event) => {
        response = await sendRequest(`/token?access_token=SECRET&state=${stateFromUrl(event.url)}`);
      },
    });

    await expect(acquireToken({
      openBrowser: false,
      signal: controller.signal,
      onEvent,
    })).rejects.toMatchObject({ code: 'AUTH_CANCELLED', name: 'AbortError' });
    expect(response.statusCode).toBe(405);
  });

  test('serves a no-store CSP-protected callback page with truthful response handling', async () => {
    let response;
    const { onEvent } = eventCollector({
      callback: async () => {
        response = await sendRequest('/callback');
      },
    });

    await expect(acquireToken({
      openBrowser: false,
      timeoutMs: 20,
      onEvent,
    })).rejects.toMatchObject({ code: 'AUTH_TIMEOUT' });

    expect(response.statusCode).toBe(200);
    expect(response.headers['Cache-Control']).toBe('no-store');
    expect(response.headers['Content-Security-Policy']).toContain("default-src 'none'");
    expect(response.headers['Referrer-Policy']).toBe('no-referrer');
    expect(response.body).toContain("method: 'POST'");
    expect(response.body).toContain('response.ok');
    expect(response.body).toContain('history.replaceState');
    expect(response.body).toContain('textContent');
    expect(response.body).not.toContain('innerHTML');
    expect(response.body).not.toContain('.finally(');
    expect(response.body).not.toContain('access_token=');
    expect(response.body).toContain('Return to the application while it verifies');
  });

  test('maps an OAuth denial to a stable token-free failure', async () => {
    const { events, onEvent } = eventCollector({
      callback: async (event) => {
        await postCallback({ error: '<private-provider-detail>', state: stateFromUrl(event.url) });
      },
    });

    await expect(acquireToken({ openBrowser: false, onEvent })).rejects.toMatchObject({
      code: 'OAUTH_ACCESS_DENIED',
      message: 'Adobe IMS authorization was denied.',
    });
    expect(JSON.stringify(events)).not.toContain('private-provider-detail');
  });

  test('returns 404 with no-store headers for unknown paths', async () => {
    const controller = new AbortController();
    let response;
    const { onEvent } = eventCollector({
      controller,
      callback: async () => {
        response = await sendRequest('/unknown');
      },
    });
    await expect(acquireToken({
      openBrowser: false,
      signal: controller.signal,
      onEvent,
    })).rejects.toMatchObject({ code: 'AUTH_CANCELLED' });
    expect(response.statusCode).toBe(404);
    expect(response.headers['Cache-Control']).toBe('no-store');
  });
});

describe('attempt lifecycle and typed failures', () => {
  test('fails before binding when passed an already-aborted signal', async () => {
    const controller = new AbortController();
    controller.abort();
    await expect(acquireToken({ signal: controller.signal })).rejects.toMatchObject({
      code: 'AUTH_CANCELLED',
      name: 'AbortError',
    });
    expect(mockHttpCreate).not.toHaveBeenCalled();
  });

  test('cancels an active attempt and force-closes its listener', async () => {
    const controller = new AbortController();
    const { onEvent } = eventCollector({ controller });
    await expect(acquireToken({
      openBrowser: false,
      signal: controller.signal,
      onEvent,
    })).rejects.toMatchObject({ code: 'AUTH_CANCELLED', name: 'AbortError' });
    expect(currentServer.close).toHaveBeenCalledTimes(1);
    expect(currentServer.closeAllConnections).toHaveBeenCalledTimes(1);
    expect(mockStoreToken).not.toHaveBeenCalled();
  });

  test('times out deterministically and closes the listener', async () => {
    const { onEvent } = eventCollector();
    await expect(acquireToken({
      openBrowser: false,
      timeoutMs: 20,
      onEvent,
    })).rejects.toMatchObject({ code: 'AUTH_TIMEOUT', retryable: true });
    expect(currentServer.close).toHaveBeenCalledTimes(1);
    expect(currentServer.closeAllConnections).toHaveBeenCalledTimes(1);
  });

  test('classifies a fixed-port collision before emitting a URL or opening a browser', async () => {
    listenError = Object.assign(new Error('private operating system detail'), {
      code: 'EADDRINUSE',
    });
    const onEvent = jest.fn();
    await expect(acquireToken({ onEvent })).rejects.toMatchObject({
      code: 'CALLBACK_PORT_IN_USE',
      retryable: true,
      message: 'Another authentication attempt is already using callback port 9898.',
    });
    expect(onEvent).not.toHaveBeenCalled();
    expect(mockOpen).not.toHaveBeenCalled();
  });

  test('cleans up when browser launch fails without exposing the nested error', async () => {
    mockOpen.mockRejectedValueOnce(new Error('secret nested platform detail'));
    const { events, onEvent } = eventCollector();
    await expect(acquireToken({ onEvent })).rejects.toMatchObject({
      code: 'BROWSER_OPEN_FAILED',
      message: 'The system browser could not be opened.',
    });
    expect(JSON.stringify(events)).not.toContain('secret nested platform detail');
    expect(currentServer.closeAllConnections).toHaveBeenCalledTimes(1);
  });

  test('cleans up when the URL event consumer fails', async () => {
    const onEvent = jest.fn(async () => { throw new Error('private sink detail'); });
    await expect(acquireToken({ openBrowser: false, onEvent })).rejects.toMatchObject({
      code: 'OUTPUT_FAILED',
      message: 'Authentication event delivery failed.',
    });
    expect(currentServer.closeAllConnections).toHaveBeenCalledTimes(1);
    expect(mockOpen).not.toHaveBeenCalled();
  });

  test.each([
    ['zero timeout', { timeoutMs: 0 }],
    ['negative timeout', { timeoutMs: -1 }],
    ['oversized timeout', { timeoutMs: 30 * 60 * 1000 + 1 }],
    ['invalid callback', { onEvent: 'not-a-function' }],
    ['invalid browser flag', { openBrowser: 'no' }],
    ['invalid reauthentication flag', { reauthenticate: 'yes' }],
  ])('rejects %s before starting an attempt', async (label, options) => {
    await expect(acquireToken(options)).rejects.toMatchObject({ code: 'INVALID_ARGUMENT' });
    expect(mockHttpCreate).not.toHaveBeenCalled();
  });
});

describe('legacy persistence and logout', () => {
  test('persists the acquired token and emits only token-free completion metadata', async () => {
    const events = [];
    completeFromOpen('SAVED_TOKEN', '3600');
    const token = await getValidToken({
      log: () => {},
      onEvent: async (event) => { events.push(event); },
    });

    expect(token).toBe('SAVED_TOKEN');
    expect(mockStoreToken).toHaveBeenCalledWith(
      expect.objectContaining({
        access_token: 'SAVED_TOKEN',
        expires_at: expect.any(Number),
      }),
    );
    expect(events.at(-1)).toMatchObject({ event: 'completed', persisted: true });
    expect(JSON.stringify(events)).not.toContain('SAVED_TOKEN');
  });

  test('maps storage failure without leaking nested filesystem details', async () => {
    completeFromOpen('TOKEN');
    mockStoreToken.mockRejectedValueOnce(new Error('/private/path detail'));
    await expect(getValidToken({ log: () => {} })).rejects.toMatchObject({
      code: 'STORE_FAILED',
      message: 'The acquired token could not be stored.',
    });
  });

  test('removes the token file when it exists', async () => {
    await clearStoredToken();
    expect(mockClearStoredToken).toHaveBeenCalledTimes(1);
  });

  test('delegates cache absence handling to the secure storage module', async () => {
    await clearStoredToken();
    expect(mockClearStoredToken).toHaveBeenCalledTimes(1);
  });
});
