import { jest } from '@jest/globals';
import os from 'os';
import path from 'path';

// ─── Mock fs-extra ────────────────────────────────────────────────────────────

const mockFs = {
  pathExists: jest.fn(),
  readJson: jest.fn(),
  writeJson: jest.fn(),
  ensureDir: jest.fn(),
  remove: jest.fn(),
};
jest.unstable_mockModule('fs-extra', () => ({ default: mockFs, ...mockFs }));

// ─── Mock open ────────────────────────────────────────────────────────────────

const mockOpen = jest.fn();
jest.unstable_mockModule('open', () => ({ default: mockOpen }));

// ─── Mock http ────────────────────────────────────────────────────────────────

let capturedRequestHandler;
let serverListenCallback;
const mockServer = {
  listen: jest.fn((port, host, cb) => { if (cb) cb(); }),
  close: jest.fn(),
  on: jest.fn(),
};
const mockHttpCreate = jest.fn((handler) => {
  capturedRequestHandler = handler;
  return mockServer;
});
jest.unstable_mockModule('http', () => ({ default: { createServer: mockHttpCreate } }));

// ─── Import SUT after mocks ───────────────────────────────────────────────────

const TOKEN_FILE = path.join(os.homedir(), '.aem', 'da-token.json');

const { getValidToken, clearStoredToken } = await import('../src/auth.js');

// ─── Helpers ──────────────────────────────────────────────────────────────────

function makeReq(pathname, params = {}) {
  const qs = new URLSearchParams(params).toString();
  const url = qs ? `${pathname}?${qs}` : pathname;
  return { url };
}

function makeRes() {
  return {
    statusCode: null,
    body: '',
    writeHead: jest.fn(function (code) { this.statusCode = code; }),
    end: jest.fn(function (data = '') { this.body += data; }),
  };
}

/**
 * Reads the state nonce out of the authorize URL handed to the mocked `open`.
 */
function currentState() {
  const calls = mockOpen.mock.calls;
  const [authUrl] = calls[calls.length - 1];
  return new URL(authUrl).searchParams.get('state');
}

/**
 * Simulates a browser completing the OAuth callback:
 *   1. GET /callback  — server responds with the HTML redirect page
 *   2. GET /token     — page JS calls this with the access_token
 */
function simulateBrowserCallback(token, expiresIn = 3600, state = currentState()) {
  // Hit /callback
  capturedRequestHandler(makeReq('/callback'), makeRes());
  // Hit /token
  const tokenRes = makeRes();
  capturedRequestHandler(
    makeReq('/token', { access_token: token, expires_in: String(expiresIn), state }),
    tokenRes,
  );
  return tokenRes;
}

// ─── Tests ────────────────────────────────────────────────────────────────────

beforeEach(() => {
  jest.clearAllMocks();
  mockFs.ensureDir.mockResolvedValue(undefined);
  mockFs.writeJson.mockResolvedValue(undefined);
  mockFs.remove.mockResolvedValue(undefined);
  mockOpen.mockResolvedValue(undefined);
});

describe('getValidToken — override', () => {
  test('returns the override token without touching storage or browser', async () => {
    const token = await getValidToken({ override: 'MY_HARDCODED_TOKEN' });
    expect(token).toBe('MY_HARDCODED_TOKEN');
    expect(mockFs.pathExists).not.toHaveBeenCalled();
    expect(mockOpen).not.toHaveBeenCalled();
  });
});

describe('getValidToken — cached token', () => {
  test('returns a valid cached token without opening the browser', async () => {
    const expiresAt = Date.now() + 60 * 60 * 1000; // 1 hour from now
    mockFs.pathExists.mockResolvedValue(true);
    mockFs.readJson.mockResolvedValue({ access_token: 'CACHED_TOKEN', expires_at: expiresAt });

    const token = await getValidToken();

    expect(token).toBe('CACHED_TOKEN');
    expect(mockOpen).not.toHaveBeenCalled();
  });

  test('does not use a token that expires within the 60s clock-skew buffer', async () => {
    const expiresAt = Date.now() + 30 * 1000; // 30 s — inside the buffer
    mockFs.pathExists.mockResolvedValue(true);
    mockFs.readJson.mockResolvedValue({ access_token: 'EXPIRING_SOON', expires_at: expiresAt });

    // Simulate browser completing the flow
    const browserToken = 'FRESH_TOKEN';
    mockOpen.mockImplementationOnce(async () => {
      simulateBrowserCallback(browserToken);
    });

    const token = await getValidToken({ log: () => {} });

    expect(token).toBe(browserToken);
    expect(mockOpen).toHaveBeenCalledTimes(1);
  });

  test('treats a legacy token without expires_at as expired', async () => {
    mockFs.pathExists.mockResolvedValue(true);
    mockFs.readJson.mockResolvedValue({ access_token: 'LEGACY_TOKEN' }); // no expires_at

    const browserToken = 'NEW_TOKEN';
    mockOpen.mockImplementationOnce(async () => { simulateBrowserCallback(browserToken); });

    const token = await getValidToken({ log: () => {} });

    expect(token).toBe(browserToken);
  });
});

describe('getValidToken — browser login flow', () => {
  test('opens the IMS auth URL in the browser', async () => {
    mockFs.pathExists.mockResolvedValue(false);

    const browserToken = 'BROWSER_TOKEN';
    mockOpen.mockImplementationOnce(async () => { simulateBrowserCallback(browserToken); });

    await getValidToken({ log: () => {} });

    expect(mockOpen).toHaveBeenCalledTimes(1);
    const [url] = mockOpen.mock.calls[0];
    expect(url).toMatch(/^https:\/\/ims-na1\.adobelogin\.com\/ims\/authorize\/v2/);
    expect(url).toContain('response_type=token');
    expect(url).toContain('client_id=darkalley');
    expect(url).toContain('redirect_uri=http%3A%2F%2Flocalhost%3A9898%2Fcallback');
  });

  test('returns the token received from the browser', async () => {
    mockFs.pathExists.mockResolvedValue(false);
    const browserToken = 'FRESH_BROWSER_TOKEN';
    mockOpen.mockImplementationOnce(async () => { simulateBrowserCallback(browserToken); });

    const token = await getValidToken({ log: () => {} });

    expect(token).toBe(browserToken);
  });

  test('persists the token with a computed expires_at', async () => {
    mockFs.pathExists.mockResolvedValue(false);
    const expiresIn = 3600;
    const before = Date.now();

    mockOpen.mockImplementationOnce(async () => { simulateBrowserCallback('SAVED_TOKEN', expiresIn); });

    await getValidToken({ log: () => {} });

    const after = Date.now();
    expect(mockFs.writeJson).toHaveBeenCalledTimes(1);
    const [filePath, data] = mockFs.writeJson.mock.calls[0];
    expect(filePath).toBe(TOKEN_FILE);
    expect(data.access_token).toBe('SAVED_TOKEN');
    expect(data.expires_at).toBeGreaterThanOrEqual(before + expiresIn * 1000);
    expect(data.expires_at).toBeLessThanOrEqual(after + expiresIn * 1000);
  });

  test('rejects when the browser reports an error', async () => {
    mockFs.pathExists.mockResolvedValue(false);

    mockOpen.mockImplementationOnce(async () => {
      capturedRequestHandler(makeReq('/callback'), makeRes());
      capturedRequestHandler(
        makeReq('/token', { error: 'access_denied', state: currentState() }),
        makeRes(),
      );
    });

    await expect(getValidToken({ log: () => {} })).rejects.toThrow('access_denied');
  });

  test('includes a state (CSRF nonce) in the authorize URL', async () => {
    mockFs.pathExists.mockResolvedValue(false);
    mockOpen.mockImplementationOnce(async () => { simulateBrowserCallback('T'); });

    await getValidToken({ log: () => {} });

    const [url] = mockOpen.mock.calls[0];
    expect(new URL(url).searchParams.get('state')).toMatch(/^[a-f0-9]{32}$/);
  });

  test('ignores a /token callback with a mismatched state (fixation attempt)', async () => {
    mockFs.pathExists.mockResolvedValue(false);
    mockOpen.mockImplementationOnce(async () => {
      const attackerRes = makeRes();
      capturedRequestHandler(
        makeReq('/token', { access_token: 'ATTACKER_TOKEN', state: 'WRONG' }),
        attackerRes,
      );
      expect(attackerRes.statusCode).toBe(403);
      // Server still listening, so the genuine callback completes.
      simulateBrowserCallback('GENUINE_TOKEN');
    });

    const token = await getValidToken({ log: () => {} });

    expect(token).toBe('GENUINE_TOKEN');
    expect(mockFs.writeJson.mock.calls[0][1].access_token).toBe('GENUINE_TOKEN');
  });
});

describe('getValidToken — /callback HTML', () => {
  // These tests trigger the browser flow but don't complete it (no /token call).
  // The server times out after 50 ms, which is fine — we only care about the
  // response to the specific route under test.

  test('/callback serves HTML that contains the fragment-reading script', async () => {
    mockFs.pathExists.mockResolvedValue(false);
    let callbackRes;
    mockOpen.mockImplementationOnce(async () => {
      // waitForToken() ran before open() so capturedRequestHandler is set here
      callbackRes = makeRes();
      capturedRequestHandler(makeReq('/callback'), callbackRes);
      // Deliberately do NOT call /token — let the timeout reject
    });

    await getValidToken({ log: () => {}, timeoutMs: 50 }).catch(() => {});

    expect(callbackRes.statusCode).toBe(200);
    expect(callbackRes.body).toContain('access_token');
    expect(callbackRes.body).toContain('/token');
  });

  test('/callback returns 200', async () => {
    mockFs.pathExists.mockResolvedValue(false);
    let callbackRes;
    mockOpen.mockImplementationOnce(async () => {
      callbackRes = makeRes();
      capturedRequestHandler(makeReq('/callback'), callbackRes);
    });

    await getValidToken({ log: () => {}, timeoutMs: 50 }).catch(() => {});
    expect(callbackRes.statusCode).toBe(200);
  });

  test('unknown paths return 404', async () => {
    mockFs.pathExists.mockResolvedValue(false);
    let unknownRes;
    mockOpen.mockImplementationOnce(async () => {
      unknownRes = makeRes();
      capturedRequestHandler(makeReq('/unknown'), unknownRes);
    });

    await getValidToken({ log: () => {}, timeoutMs: 50 }).catch(() => {});
    expect(unknownRes.statusCode).toBe(404);
  });
});

describe('clearStoredToken', () => {
  test('removes the token file when it exists', async () => {
    mockFs.pathExists.mockResolvedValue(true);
    await clearStoredToken();
    expect(mockFs.remove).toHaveBeenCalledWith(TOKEN_FILE);
  });

  test('does nothing when the token file does not exist', async () => {
    mockFs.pathExists.mockResolvedValue(false);
    await clearStoredToken();
    expect(mockFs.remove).not.toHaveBeenCalled();
  });
});
