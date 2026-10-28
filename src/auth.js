/*
 * Copyright 2026 Adobe. All rights reserved.
 * This file is licensed to you under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under
 * the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR REPRESENTATIONS
 * OF ANY KIND, either express or implied. See the License for the specific language
 * governing permissions and limitations under the License.
 */

/**
 * Standalone IMS OAuth 2.0 implicit-flow auth module for da.live / DA MCP.
 *
 * `getValidToken()` preserves the original cache-owning contract.
 * `acquireToken()` is the caller-owned contract: it never reads or writes the cache.
 */

import http from 'http';
import crypto from 'crypto';
import open from 'open';
import {
  TOKEN_FILE,
  clearStoredToken as clearTokenFile,
  loadStoredToken,
  storeToken,
} from './storage.js';

// ─── Constants ───────────────────────────────────────────────────────────────

const IMS_ORIGIN = 'https://ims-na1.adobelogin.com';
const CLIENT_ID = 'darkalley';
const SCOPE = [
  'ab.manage',
  'AdobeID',
  'gnav',
  'openid',
  'org.read',
  'read_organizations',
  'session',
  'aem.frontend.all',
  'additional_info.ownerOrg',
  'additional_info.projectedProductContext',
  'account_cluster.read',
].join(',');
const CALLBACK_PORT = 9898;
const REDIRECT_URI = `http://localhost:${CALLBACK_PORT}/callback`;
const DEFAULT_TIMEOUT_MS = 5 * 60 * 1000;
const MAX_TIMEOUT_MS = 2_147_483_647;
const HEARTBEAT_MS = 15 * 1000;
const MAX_CALLBACK_BODY_BYTES = 64 * 1024;
const MAX_TOKEN_BYTES = 64 * 1024;
const MAX_EXPIRY_MS = 30 * 24 * 60 * 60 * 1000;

export const AUTH_EVENT_SCHEMA = 'da-auth-helper.event.v1';

/** A token-free, stable failure exposed to programmatic callers. */
export class AuthError extends Error {
  constructor(code, message, { retryable = false, cause } = {}) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = 'AuthError';
    this.code = code;
    this.retryable = retryable;
  }
}

function abortError() {
  const error = new AuthError('AUTH_CANCELLED', 'Authentication was cancelled.', {
    retryable: true,
  });
  error.name = 'AbortError';
  return error;
}

function validateAttemptOptions({
  reauthenticate = false,
  openBrowser = true,
  timeoutMs = DEFAULT_TIMEOUT_MS,
  signal,
  onEvent,
} = {}) {
  if (typeof reauthenticate !== 'boolean') {
    throw new AuthError('INVALID_ARGUMENT', 'reauthenticate must be a boolean.');
  }
  if (typeof openBrowser !== 'boolean') {
    throw new AuthError('INVALID_ARGUMENT', 'openBrowser must be a boolean.');
  }
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0 || timeoutMs > MAX_TIMEOUT_MS) {
    throw new AuthError(
      'INVALID_ARGUMENT',
      `timeoutMs must be a positive integer no greater than ${MAX_TIMEOUT_MS}.`,
    );
  }
  if (onEvent !== undefined && typeof onEvent !== 'function') {
    throw new AuthError('INVALID_ARGUMENT', 'onEvent must be a function.');
  }
  if (signal !== undefined
    && (typeof signal !== 'object'
      || typeof signal.addEventListener !== 'function'
      || typeof signal.removeEventListener !== 'function')) {
    throw new AuthError('INVALID_ARGUMENT', 'signal must be an AbortSignal.');
  }
  if (signal?.aborted) throw abortError();

  return {
    reauthenticate,
    openBrowser,
    timeoutMs,
    signal,
    onEvent,
  };
}

function createEventDispatcher(onEvent) {
  let tail = Promise.resolve();
  return (event) => {
    if (!onEvent) return Promise.resolve();
    const record = Object.freeze({ schema: AUTH_EVENT_SCHEMA, ...event });
    const delivery = tail.then(async () => {
      try {
        await onEvent(record);
      } catch (cause) {
        if (cause instanceof AuthError) throw cause;
        throw new AuthError('OUTPUT_FAILED', 'Authentication event delivery failed.', { cause });
      }
    });
    tail = delivery;
    return delivery;
  };
}

function logMessage(log, message) {
  if (!log) return;
  try {
    log(message);
  } catch (cause) {
    throw new AuthError('OUTPUT_FAILED', 'Authentication status output failed.', { cause });
  }
}

// ─── Token validity and metadata ─────────────────────────────────────────────

function isTokenExpired(stored) {
  if (stored.expires_at) {
    // 60-second early buffer for clock skew.
    return Date.now() >= (stored.expires_at - 60_000);
  }
  // Legacy tokens without expires_at are treated as expired.
  return true;
}

function jwtExpiry(token, now) {
  try {
    const parts = token.split('.');
    if (parts.length < 2) return null;
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    if (!Number.isFinite(payload.exp)) return null;
    const expiresAt = payload.exp * 1000;
    if (!Number.isSafeInteger(expiresAt)) return null;
    const remainingMs = expiresAt - now;
    if (remainingMs <= 0 || remainingMs > MAX_EXPIRY_MS) return null;
    return expiresAt;
  } catch {
    return null;
  }
}

function expiryMetadata(token) {
  const now = Date.now();
  const jwtExpiresAt = jwtExpiry(token, now);
  if (jwtExpiresAt !== null) {
    return { expiresAt: jwtExpiresAt, expirySource: 'jwt-exp' };
  }
  // IMS deployments have emitted `expires_in` in both seconds and
  // milliseconds. Never infer a unit from magnitude: an opaque token gets an
  // unknown expiry and therefore cannot be over-trusted by the cache.
  return { expiresAt: null, expirySource: null };
}

// ─── OAuth callback server ───────────────────────────────────────────────────

function responseHeaders(contentType) {
  return {
    'Cache-Control': 'no-store',
    'Content-Type': contentType,
    'Referrer-Policy': 'no-referrer',
    'X-Content-Type-Options': 'nosniff',
  };
}

function sendResponse(res, statusCode, body = '', headers = {}) {
  if (res.headersSent || res.writableEnded) return;
  res.writeHead(statusCode, {
    ...responseHeaders('text/plain; charset=utf-8'),
    Connection: 'close',
    ...headers,
  });
  res.end(body);
}

function callbackHtml(cspNonce) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>DA authorization</title>
</head>
<body>
  <main id="status" aria-live="polite"><p>Completing authorization…</p></main>
  <script nonce="${cspNonce}">
    const status = document.getElementById('status');
    const render = (headingText, detailText) => {
      const heading = document.createElement('h1');
      heading.textContent = headingText;
      const detail = document.createElement('p');
      detail.textContent = detailText;
      status.replaceChildren(heading, detail);
    };
    const params = new URLSearchParams(window.location.hash.substring(1));
    window.history.replaceState(null, '', window.location.pathname);
    fetch('/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: params.toString(),
      cache: 'no-store',
      credentials: 'omit',
      referrerPolicy: 'no-referrer',
    }).then((response) => {
      if (!response.ok) throw new Error('callback rejected');
      render(
        'Authorization received.',
        'Return to the application while it verifies and stores the credential.',
      );
    }).catch(() => {
      render(
        'Authorization was not received.',
        'Return to the application and retry the login.',
      );
    });
  </script>
</body>
</html>`;
}

function readRequestBody(req) {
  return new Promise((resolve, reject) => {
    let settled = false;
    let size = 0;
    const chunks = [];

    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      if (error) reject(error);
      else resolve(value);
    };

    req.on('data', (chunk) => {
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      size += buffer.length;
      if (size > MAX_CALLBACK_BODY_BYTES) {
        finish(new AuthError('CALLBACK_INVALID', 'The authorization callback was invalid.'));
        return;
      }
      chunks.push(buffer);
    });
    req.on('end', () => finish(null, Buffer.concat(chunks).toString('utf8')));
    req.on('aborted', () => finish(
      new AuthError('CALLBACK_INVALID', 'The authorization callback was interrupted.'),
    ));
    req.on('error', () => finish(
      new AuthError('CALLBACK_INVALID', 'The authorization callback was invalid.'),
    ));
  });
}

function callbackError(code, message, retryable = false) {
  return new AuthError(code, message, { retryable });
}

function createCallbackAttempt({ expectedState, timeoutMs, signal, emit }) {
  const loopbackHosts = ['::1', '127.0.0.1'];
  const servers = [];
  let timeout;
  let settled = false;
  let bindingFinished = false;
  let finalizing = false;
  let terminal;
  let readySettled = false;
  let resolveReady;
  let rejectReady;
  let resolveResult;
  let rejectResult;

  const ready = new Promise((resolve, reject) => {
    resolveReady = resolve;
    rejectReady = reject;
  });
  const result = new Promise((resolve, reject) => {
    resolveResult = resolve;
    rejectResult = reject;
  });
  // The owner awaits `ready` before `result`; attach a handler immediately so
  // an early bind/abort failure cannot become an unhandled rejection.
  void result.catch(() => {});

  const closeEntry = (entry, force) => new Promise((resolve) => {
    if (!entry.bound) {
      resolve();
      return;
    }

    entry.bound = false;
    let closed = false;
    const done = () => {
      if (closed) return;
      closed = true;
      resolve();
    };

    try {
      entry.server.close(done);
    } catch {
      done();
    }

    if (force) {
      try {
        entry.server.closeAllConnections?.();
      } catch {
        // Best-effort cleanup for Node versions that expose this method.
      }
      for (const socket of entry.sockets) {
        try {
          socket.destroy();
        } catch {
          // Best-effort socket cleanup.
        }
      }
      done();
    }
  });

  const finalize = () => {
    if (finalizing || !bindingFinished || !terminal) return;
    finalizing = true;

    if (!readySettled && terminal.error) {
      readySettled = true;
      rejectReady(terminal.error);
    }

    void Promise.all(servers.map((entry) => closeEntry(entry, terminal.force))).then(() => {
      if (terminal.error) rejectResult(terminal.error);
      else resolveResult(terminal.value);
    });
  };

  const settle = (error, value, force = false) => {
    if (settled) return;
    settled = true;
    terminal = { error, value, force };
    clearTimeout(timeout);
    signal?.removeEventListener('abort', onAbort);
    finalize();
  };

  const onAbort = () => settle(abortError(), undefined, true);

  const rejectCallback = async (res, code, statusCode = 400) => {
    sendResponse(res, statusCode, 'Authorization callback rejected.');
    try {
      await emit({ event: 'callback_rejected', code });
    } catch (error) {
      settle(error, undefined, true);
    }
  };

  const settleAfterResponse = (res, statusCode, body, error, value) => {
    let finished = false;
    const finish = () => {
      if (finished) return;
      finished = true;
      settle(error, value, true);
    };
    if (typeof res.once === 'function') {
      res.once('finish', finish);
      res.once('close', finish);
    }
    sendResponse(res, statusCode, body);
    if (typeof res.once !== 'function') finish();
  };

  const handleRequest = async (req, res) => {
    let url;
    try {
      url = new URL(req.url, `http://localhost:${CALLBACK_PORT}`);
    } catch {
      sendResponse(res, 400, 'Invalid request.');
      return;
    }

    if (url.pathname === '/callback' && (req.method === undefined || req.method === 'GET')) {
      const nonce = crypto.randomBytes(18).toString('base64url');
      sendResponse(res, 200, callbackHtml(nonce), {
        ...responseHeaders('text/html; charset=utf-8'),
        'Content-Security-Policy': `default-src 'none'; script-src 'nonce-${nonce}'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`,
      });
      return;
    }

    if (url.pathname === '/token' && req.method === 'POST') {
      const contentType = String(req.headers?.['content-type'] || '').toLowerCase();
      if (!contentType.startsWith('application/x-www-form-urlencoded')) {
        await rejectCallback(res, 'CALLBACK_INVALID', 415);
        return;
      }

      let body;
      try {
        body = await readRequestBody(req);
      } catch {
        await rejectCallback(res, 'CALLBACK_INVALID');
        return;
      }

      const params = new URLSearchParams(body);
      const returnedState = params.get('state');
      if (!returnedState || returnedState !== expectedState) {
        await rejectCallback(res, 'CALLBACK_STATE_MISMATCH', 403);
        return;
      }

      const token = params.get('access_token');
      const oauthFailure = params.has('error');

      if (oauthFailure) {
        settleAfterResponse(
          res,
          400,
          'Authorization was denied.',
          callbackError('OAUTH_ACCESS_DENIED', 'Adobe IMS authorization was denied.', true),
        );
        return;
      }

      if (!token || Buffer.byteLength(token, 'utf8') > MAX_TOKEN_BYTES) {
        await rejectCallback(res, 'CALLBACK_INVALID');
        return;
      }

      settleAfterResponse(res, 204, '', null, { token });
      return;
    }

    if (url.pathname === '/token') {
      sendResponse(res, 405, 'Method not allowed.', { Allow: 'POST' });
      return;
    }

    sendResponse(res, 404, 'Not found.');
  };

  const bindHost = (host) => new Promise((resolve) => {
    const entry = {
      host,
      server: http.createServer((req, res) => {
        void handleRequest(req, res).catch(() => {
          settleAfterResponse(
            res,
            500,
            'Authorization callback failed.',
            callbackError(
              'CALLBACK_INVALID',
              'The authorization callback could not be processed.',
              true,
            ),
          );
        });
      }),
      sockets: new Set(),
      bound: false,
      bindFinished: false,
    };
    servers.push(entry);

    entry.server.requestTimeout = timeoutMs;
    entry.server.headersTimeout = timeoutMs;
    entry.server.on('connection', (socket) => {
      entry.sockets.add(socket);
      socket.setTimeout?.(timeoutMs, () => socket.destroy());
      socket.once?.('close', () => entry.sockets.delete(socket));
    });

    const finishBind = (outcome) => {
      if (entry.bindFinished) return;
      entry.bindFinished = true;
      resolve(outcome);
    };

    entry.server.on('error', (cause) => {
      if (!entry.bindFinished) {
        if (['EADDRNOTAVAIL', 'EAFNOSUPPORT'].includes(cause?.code)) {
          finishBind({ supported: false, entry });
          return;
        }
        const portInUse = cause?.code === 'EADDRINUSE';
        finishBind({
          error: callbackError(
            portInUse ? 'CALLBACK_PORT_IN_USE' : 'CALLBACK_SERVER_FAILED',
            portInUse
              ? `Another authentication attempt is already using callback port ${CALLBACK_PORT}.`
              : `The authentication callback server could not bind to port ${CALLBACK_PORT}.`,
            true,
          ),
          entry,
        });
        return;
      }
      settle(callbackError(
        'CALLBACK_SERVER_FAILED',
        `The authentication callback server failed on port ${CALLBACK_PORT}.`,
        true,
      ), undefined, true);
    });

    try {
      entry.server.listen(CALLBACK_PORT, host, () => {
        entry.bound = true;
        finishBind({ supported: true, entry });
      });
    } catch {
      finishBind({
        error: callbackError(
          'CALLBACK_SERVER_FAILED',
          `The authentication callback server could not bind to port ${CALLBACK_PORT}.`,
          true,
        ),
        entry,
      });
    }
  });

  timeout = setTimeout(() => {
    settle(callbackError(
      'AUTH_TIMEOUT',
      'Authentication timed out before a valid callback was received.',
      true,
    ), undefined, true);
  }, timeoutMs);
  signal?.addEventListener('abort', onAbort, { once: true });

  void Promise.all(loopbackHosts.map(bindHost)).then((outcomes) => {
    bindingFinished = true;
    if (!settled) {
      const failure = outcomes.find(({ error }) => error)?.error;
      const supported = outcomes.some(({ supported }) => supported);
      if (failure) settle(failure, undefined, true);
      else if (!supported) {
        settle(callbackError(
          'CALLBACK_SERVER_FAILED',
          'No supported localhost address was available for authentication.',
          true,
        ), undefined, true);
      } else if (!readySettled) {
        readySettled = true;
        resolveReady();
      }
    }
    finalize();
  });

  return {
    ready,
    result,
    cancel(error) {
      settle(error, undefined, true);
    },
    isSettled() {
      return settled;
    },
  };
}

function authorizationUrl({ state }) {
  const params = new URLSearchParams({
    response_type: 'token',
    client_id: CLIENT_ID,
    scope: SCOPE,
    redirect_uri: REDIRECT_URI,
    prompt: 'login',
    profile_filter: false,
    state,
  });
  return `${IMS_ORIGIN}/ims/authorize/v2?${params}`;
}

function createLifecycleGuard({ timeoutMs, signal }) {
  let rejectGuard;
  let disposed = false;
  const deadlineAt = Date.now() + timeoutMs;
  const promise = new Promise((resolve, reject) => {
    rejectGuard = reject;
  });
  void promise.catch(() => {});

  const onAbort = () => rejectGuard(abortError());
  const timeout = setTimeout(() => rejectGuard(callbackError(
    'AUTH_TIMEOUT',
    'Authentication timed out before the operation completed.',
    true,
  )), timeoutMs);
  signal?.addEventListener('abort', onAbort, { once: true });

  return {
    deadlineAt,
    promise,
    dispose() {
      if (disposed) return;
      disposed = true;
      clearTimeout(timeout);
      signal?.removeEventListener('abort', onAbort);
    },
  };
}

async function whileAttemptActive(operation, attempt, guard) {
  // URL delivery and browser launch are caller/platform operations. An abort,
  // bind failure, or timeout must still be able to end the attempt while one
  // of those operations is pending.
  const failure = attempt.result.then(
    () => new Promise(() => {}),
    (error) => Promise.reject(error),
  );
  return Promise.race([operation, failure, guard.promise]);
}

async function openWhileAttemptActive(operation, attempt, guard) {
  return Promise.race([
    operation.then(() => ({ source: 'browser' })),
    attempt.result.then((value) => ({ source: 'callback', value })),
    guard.promise,
  ]);
}

async function browserAttempt({
  reauthenticate,
  openBrowser,
  timeoutMs,
  signal,
  emit,
  log,
  guard,
}) {
  const state = crypto.randomBytes(16).toString('hex');
  const authUrl = authorizationUrl({ state });
  const { deadlineAt } = guard;
  const attempt = createCallbackAttempt({
    expectedState: state,
    timeoutMs,
    signal,
    emit,
  });
  let heartbeat;
  let heartbeatBusy = false;

  try {
    await attempt.ready;
    await whileAttemptActive(emit({
      event: 'authorization_url',
      url: authUrl,
      redirectUri: REDIRECT_URI,
      callbackPort: CALLBACK_PORT,
      deadlineAt,
      reauthenticationRequested: reauthenticate,
    }), attempt, guard);

    logMessage(log, openBrowser
      ? 'Opening browser for da.live login…'
      : 'Browser launch suppressed; open the authorization URL in the caller-owned browser.');
    logMessage(log, `If the browser does not open automatically, visit:\n  ${authUrl}\n`);
    logMessage(log, 'Waiting for login to complete…');

    let callback;
    if (attempt.isSettled()) {
      callback = await Promise.race([attempt.result, guard.promise]);
    } else if (openBrowser) {
      try {
        const outcome = await openWhileAttemptActive(open(authUrl), attempt, guard);
        if (outcome.source === 'callback') callback = outcome.value;
      } catch (cause) {
        if (cause instanceof AuthError) throw cause;
        throw new AuthError(
          'BROWSER_OPEN_FAILED',
          'The system browser could not be opened.',
          { retryable: true, cause },
        );
      }
    }

    if (timeoutMs > HEARTBEAT_MS) {
      heartbeat = setInterval(() => {
        if (heartbeatBusy || attempt.isSettled()) return;
        heartbeatBusy = true;
        void emit({
          event: 'waiting',
          remainingMs: Math.max(0, deadlineAt - Date.now()),
        }).catch((error) => attempt.cancel(error)).finally(() => {
          heartbeatBusy = false;
        });
      }, HEARTBEAT_MS);
      heartbeat.unref?.();
    }

    if (!callback) callback = await Promise.race([attempt.result, guard.promise]);
    const { token } = callback;
    const { expiresAt, expirySource } = expiryMetadata(token);
    return {
      token,
      expiresAt,
      expirySource,
      tokenAcquired: true,
      persisted: false,
      reauthenticationRequested: reauthenticate,
    };
  } catch (error) {
    const normalized = error instanceof AuthError
      ? error
      : new AuthError('CALLBACK_INVALID', 'Authentication failed.', {
        retryable: true,
        cause: error,
      });
    attempt.cancel(normalized);
    throw normalized;
  } finally {
    clearInterval(heartbeat);
  }
}

async function emitCompleted(emit, result, guard) {
  await Promise.race([emit({
    event: 'completed',
    tokenAcquired: result.tokenAcquired,
    persisted: result.persisted,
    expiresAt: result.expiresAt,
    expirySource: result.expirySource,
    reauthenticationRequested: result.reauthenticationRequested,
  }), guard.promise]);
}

// ─── Public API ──────────────────────────────────────────────────────────────

/**
 * Acquires a fresh caller-owned token without reading or writing the helper cache.
 *
 * @param {object} [opts]
 * @param {boolean} [opts.reauthenticate=false] - Report the attempt as reauthentication in events.
 *   Every attempt already sends IMS prompt=login.
 * @param {boolean} [opts.openBrowser=true] - Launch the OS browser when true.
 * @param {number} [opts.timeoutMs=300000] - Attempt timeout in milliseconds.
 * @param {AbortSignal} [opts.signal] - Cancels the active callback attempt.
 * @param {Function} [opts.onEvent] - Receives versioned, token-free events.
 * @returns {Promise<{token: string, expiresAt: number|null, expirySource: string|null,
 * tokenAcquired: true, persisted: false, reauthenticationRequested: boolean}>}
 */
export async function acquireToken(opts = {}) {
  const options = validateAttemptOptions(opts);
  const emit = createEventDispatcher(options.onEvent);
  const guard = createLifecycleGuard(options);
  try {
    const result = await browserAttempt({ ...options, emit, guard, log: undefined });
    await emitCompleted(emit, result, guard);
    return result;
  } finally {
    guard.dispose();
  }
}

/**
 * Returns a valid da.live / IMS access token, triggering the browser login
 * flow only when necessary. Existing default cache behavior is preserved.
 *
 * @param {object} [opts]
 * @param {string} [opts.override] - Hard-coded token; skips cache and browser flow.
 * @param {Function} [opts.log=console.info] - Human-readable status logger.
 * @param {boolean} [opts.reauthenticate=false] - Bypass the cache. Every browser attempt
 *   already sends IMS prompt=login.
 * @param {boolean} [opts.openBrowser=true] - Launch the OS browser when true.
 * @param {number} [opts.timeoutMs=300000] - Attempt timeout in milliseconds.
 * @param {AbortSignal} [opts.signal] - Cancels the active callback attempt.
 * @param {Function} [opts.onEvent] - Receives versioned, token-free events.
 * @returns {Promise<string>} valid access token
 */
export async function getValidToken({
  override,
  log = console.info,
  reauthenticate = false,
  openBrowser = true,
  timeoutMs = DEFAULT_TIMEOUT_MS,
  signal,
  onEvent,
} = {}) {
  if (override) return override;

  const options = validateAttemptOptions({
    reauthenticate,
    openBrowser,
    timeoutMs,
    signal,
    onEvent,
  });
  const emit = createEventDispatcher(onEvent);

  if (!reauthenticate) {
    let stored;
    try {
      stored = await loadStoredToken();
    } catch (cause) {
      throw new AuthError('STORE_FAILED', 'The credential cache could not be read safely.', {
        cause,
      });
    }
    if (stored?.access_token && !isTokenExpired(stored)) {
      return stored.access_token;
    }
    if (stored?.access_token) {
      logMessage(log, 'Stored token has expired. Re-authenticating…');
    }
  }

  const guard = createLifecycleGuard(options);
  try {
    const candidate = await browserAttempt({ ...options, emit, guard, log });
    try {
      await storeToken({
        access_token: candidate.token,
        expires_at: candidate.expiresAt,
      });
    } catch (cause) {
      throw new AuthError('STORE_FAILED', 'The acquired token could not be stored.', { cause });
    }

    const result = { ...candidate, persisted: true };
    logMessage(log, `Login successful. Token saved to ${TOKEN_FILE}`);
    await emitCompleted(emit, result, guard);
    return result.token;
  } finally {
    guard.dispose();
  }
}

/**
 * Clears the stored token, forcing a fresh login on the next getValidToken call.
 *
 * @returns {Promise<void>}
 */
export async function clearStoredToken() {
  try {
    await clearTokenFile();
  } catch (cause) {
    throw new AuthError('STORE_FAILED', 'The credential cache could not be cleared safely.', {
      cause,
    });
  }
}
