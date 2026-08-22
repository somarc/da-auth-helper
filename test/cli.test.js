import { jest } from '@jest/globals';

const mockAcquireToken = jest.fn();
const mockClearStoredToken = jest.fn();
const mockGetValidToken = jest.fn();

class MockAuthError extends Error {
  constructor(code, message, { retryable = false } = {}) {
    super(message);
    this.name = 'AuthError';
    this.code = code;
    this.retryable = retryable;
  }
}

jest.unstable_mockModule('../src/auth.js', () => ({
  AUTH_EVENT_SCHEMA: 'da-auth-helper.event.v1',
  AuthError: MockAuthError,
  acquireToken: mockAcquireToken,
  clearStoredToken: mockClearStoredToken,
  getValidToken: mockGetValidToken,
}));

const { parseArgs, runCli } = await import('../src/cli.js');

function outputStream({ fail = false } = {}) {
  let text = '';
  return {
    write(chunk, callback) {
      if (fail) {
        const error = new Error('private stream detail');
        callback?.(error);
        if (!callback) throw error;
        return false;
      }
      text += chunk;
      callback?.();
      return true;
    },
    get text() {
      return text;
    },
  };
}

beforeEach(() => {
  jest.clearAllMocks();
  mockClearStoredToken.mockResolvedValue(undefined);
  mockGetValidToken.mockResolvedValue('TOKEN');
  mockAcquireToken.mockResolvedValue({
    token: 'CANDIDATE',
    expiresAt: null,
    expirySource: null,
    tokenAcquired: true,
    persisted: false,
    reauthenticationRequested: false,
  });
});

describe('parseArgs', () => {
  test('keeps token as the default command', () => {
    expect(parseArgs([])).toMatchObject({
      command: 'token',
      reauthenticate: false,
      openBrowser: true,
      events: 'human',
    });
  });

  test('parses the complete caller-owned acquisition surface', () => {
    expect(parseArgs([
      'acquire',
      '--reauthenticate',
      '--no-open',
      '--timeout-ms',
      '1234',
      '--events=ndjson',
    ])).toEqual({
      command: 'acquire',
      reauthenticate: true,
      openBrowser: false,
      timeoutMs: 1234,
      events: 'ndjson',
      help: false,
    });
  });

  test.each([
    [['unknown'], 'Unknown command: unknown'],
    [['token', '--unknown'], 'Unknown option: --unknown'],
    [['token', '--timeout-ms'], '--timeout-ms requires a positive integer.'],
    [['token', '--timeout-ms', '1e3'], '--timeout-ms requires a positive integer.'],
    [['token', '--events=json'], 'Unknown option: --events=json'],
    [['logout', '--no-open'], 'logout does not accept authentication options.'],
  ])('rejects invalid arguments %#', (argv, message) => {
    expect(() => parseArgs(argv)).toThrow(message);
  });
});

describe('runCli', () => {
  test('preserves token stdout and human stderr separation', async () => {
    const stdout = outputStream();
    const stderr = outputStream();
    mockGetValidToken.mockImplementationOnce(async ({ log }) => {
      log('Waiting for login.');
      return 'SECRET_TOKEN';
    });

    await expect(runCli({ argv: ['token'], stdout, stderr })).resolves.toBe(0);

    expect(stdout.text).toBe('SECRET_TOKEN\n');
    expect(stderr.text).toBe('Waiting for login.\n');
    expect(stderr.text).not.toContain('SECRET_TOKEN');
  });

  test('keeps login as a token alias unless reauthentication is explicit', async () => {
    const stdout = outputStream();
    const stderr = outputStream();
    await runCli({ argv: ['login'], stdout, stderr });
    expect(mockGetValidToken).toHaveBeenCalledWith(expect.objectContaining({
      reauthenticate: false,
    }));
  });

  test('passes explicit acquisition controls through without adding storage', async () => {
    const stdout = outputStream();
    const stderr = outputStream();
    await runCli({
      argv: [
        'acquire',
        '--reauthenticate',
        '--no-open',
        '--timeout-ms',
        '1234',
      ],
      stdout,
      stderr,
    });

    expect(mockAcquireToken).toHaveBeenCalledWith(expect.objectContaining({
      reauthenticate: true,
      openBrowser: false,
      timeoutMs: 1234,
      onEvent: expect.any(Function),
    }));
    expect(mockGetValidToken).not.toHaveBeenCalled();
    expect(stdout.text).toBe('CANDIDATE\n');
  });

  test('emits parseable token-free NDJSON events while keeping the candidate on stdout', async () => {
    const stdout = outputStream();
    const stderr = outputStream();
    mockAcquireToken.mockImplementationOnce(async ({ onEvent }) => {
      await onEvent({
        schema: 'da-auth-helper.event.v1',
        event: 'authorization_url',
        url: 'https://ims-na1.adobelogin.com/ims/authorize/v2?state=abc',
        callbackPort: 9898,
      });
      await onEvent({
        schema: 'da-auth-helper.event.v1',
        event: 'completed',
        tokenAcquired: true,
        persisted: false,
      });
      return { token: 'SECRET_CANDIDATE' };
    });

    const code = await runCli({
      argv: ['acquire', '--no-open', '--events=ndjson'],
      stdout,
      stderr,
    });

    expect(code).toBe(0);
    expect(stdout.text).toBe('SECRET_CANDIDATE\n');
    const records = stderr.text.trim().split('\n').map((line) => JSON.parse(line));
    expect(records.map(({ event }) => event)).toEqual(['authorization_url', 'completed']);
    expect(stderr.text).not.toContain('SECRET_CANDIDATE');
  });

  test('renders a human-readable URL for plain acquire mode', async () => {
    const stdout = outputStream();
    const stderr = outputStream();
    mockAcquireToken.mockImplementationOnce(async ({ onEvent }) => {
      await onEvent({
        schema: 'da-auth-helper.event.v1',
        event: 'authorization_url',
        url: 'https://ims-na1.adobelogin.com/ims/authorize/v2?state=abc',
      });
      return { token: 'CANDIDATE' };
    });

    await runCli({ argv: ['acquire', '--no-open'], stdout, stderr });
    expect(stderr.text).toContain('Authorization URL:');
    expect(stderr.text).toContain('https://ims-na1.adobelogin.com/');
    expect(stderr.text).not.toContain('CANDIDATE');
  });

  test('prints a stable token-free NDJSON error', async () => {
    const stdout = outputStream();
    const stderr = outputStream();
    mockAcquireToken.mockRejectedValueOnce(new MockAuthError(
      'CALLBACK_PORT_IN_USE',
      'Another authentication attempt is already using callback port 9898.',
      { retryable: true },
    ));

    const code = await runCli({
      argv: ['acquire', '--events=ndjson'],
      stdout,
      stderr,
    });

    expect(code).toBe(1);
    expect(stdout.text).toBe('');
    expect(JSON.parse(stderr.text)).toEqual({
      schema: 'da-auth-helper.event.v1',
      event: 'error',
      code: 'CALLBACK_PORT_IN_USE',
      retryable: true,
      message: 'Another authentication attempt is already using callback port 9898.',
    });
  });

  test('fails unknown arguments before calling authentication', async () => {
    const stdout = outputStream();
    const stderr = outputStream();
    await expect(runCli({ argv: ['token', '--wat'], stdout, stderr })).resolves.toBe(1);
    expect(mockGetValidToken).not.toHaveBeenCalled();
    expect(stderr.text).toContain('INVALID_ARGUMENT');
  });

  test('supports logout without writing a secret', async () => {
    const stdout = outputStream();
    const stderr = outputStream();
    await expect(runCli({ argv: ['logout'], stdout, stderr })).resolves.toBe(0);
    expect(mockClearStoredToken).toHaveBeenCalledTimes(1);
    expect(stdout.text).toBe('');
    expect(stderr.text).toBe('Stored token cleared.\n');
  });

  test('renders help without invoking authentication', async () => {
    const stdout = outputStream();
    const stderr = outputStream();
    await expect(runCli({ argv: ['--help'], stdout, stderr })).resolves.toBe(0);
    expect(stderr.text).toContain('da-auth-helper acquire');
    expect(mockGetValidToken).not.toHaveBeenCalled();
  });

  test('does not copy a candidate into stderr when stdout fails', async () => {
    const stdout = outputStream({ fail: true });
    const stderr = outputStream();
    mockAcquireToken.mockResolvedValueOnce({ token: 'DO_NOT_ECHO' });

    await expect(runCli({ argv: ['acquire'], stdout, stderr })).resolves.toBe(1);
    expect(stderr.text).toContain('AUTH_FAILED');
    expect(stderr.text).not.toContain('DO_NOT_ECHO');
  });
});
