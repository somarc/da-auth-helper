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
 * Usage:
 *   import { getValidToken } from 'da-auth-helper';
 *   const token = await getValidToken();
 *
 * The token is persisted at ~/.aem/da-token.json so subsequent calls return
 * the cached token until it expires, at which point the browser flow reruns.
 */

import http from 'http';
import os from 'os';
import path from 'path';
import crypto from 'crypto';
import fse from 'fs-extra';
import open from 'open';

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
const TOKEN_FILE = path.join(os.homedir(), '.aem', 'da-token.json');

// ─── Token storage ───────────────────────────────────────────────────────────

async function loadStoredToken() {
  if (!await fse.pathExists(TOKEN_FILE)) return null;
  try {
    return await fse.readJson(TOKEN_FILE);
  } catch {
    return null;
  }
}

async function storeToken(tokenData) {
  await fse.ensureDir(path.dirname(TOKEN_FILE));
  await fse.writeJson(TOKEN_FILE, tokenData, { spaces: 2 });
}

// ─── Token validity ──────────────────────────────────────────────────────────

function isTokenExpired(stored) {
  if (stored.expires_at) {
    // 60-second early buffer for clock skew
    return Date.now() >= (stored.expires_at - 60_000);
  }
  // Legacy tokens without expires_at — treat as expired
  return true;
}

// ─── OAuth callback server ───────────────────────────────────────────────────

/**
 * Starts a local HTTP server that handles the IMS implicit-flow callback.
 *
 * IMS redirects to http://localhost:{port}/callback#access_token=TOKEN
 * The fragment never reaches the server, so /callback serves a small HTML page
 * that reads the fragment via JS and POSTs the token to /token.
 *
 * @param {object} [opts]
 * @param {number} [opts.timeoutMs=300000] - How long to wait before giving up (ms).
 * @param {string} [opts.expectedState] - CSRF nonce that the IMS callback must echo back.
 * @returns {Promise<{token: string, expiresIn: number|null}>}
 */
function waitForToken({ timeoutMs = 5 * 60 * 1000, expectedState } = {}) {
  return new Promise((resolve, reject) => {
    let timeout;

    const server = http.createServer((req, res) => {
      const url = new URL(req.url, `http://localhost:${CALLBACK_PORT}`);

      // Step 1 — IMS lands here. Serve a page that reads the fragment and
      // forwards the token to /token as a query-param fetch.
      if (url.pathname === '/callback') {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(`<!DOCTYPE html>
<html>
<head><title>Logging in…</title></head>
<body>
<script>
  const p = new URLSearchParams(window.location.hash.substring(1));
  const token = p.get('access_token');
  const expiresIn = p.get('expires_in');
  const error = p.get('error');
  const state = p.get('state');
  const stateParam = state ? '&state=' + encodeURIComponent(state) : '';
  const dest = token
    ? '/token?access_token=' + encodeURIComponent(token)
      + (expiresIn ? '&expires_in=' + encodeURIComponent(expiresIn) : '')
      + stateParam
    : '/token?error=' + encodeURIComponent(error || 'unknown') + stateParam;
  fetch(dest).finally(() => {
    if (token) {
      window.location.href = 'https://tools.aem.live/cli/logged-in';
    } else {
      document.body.innerHTML = '<h2>Login failed.</h2><p>' + (error || 'Unknown error') + '</p>';
    }
  });
</script>
</body>
</html>`);
        return;
      }

      // Step 2 — The page above GETs /token with the access_token query-param.
      if (url.pathname === '/token') {
        // Reject forged callbacks that do not carry the CSRF state nonce we
        // generated for this login. Ignore them without tearing down the
        // server so the genuine IMS callback can still complete.
        const returnedState = url.searchParams.get('state');
        if (!returnedState || returnedState !== expectedState) {
          res.writeHead(403);
          res.end();
          return;
        }
        const token = url.searchParams.get('access_token');
        const expiresIn = url.searchParams.get('expires_in');
        const error = url.searchParams.get('error');
        res.writeHead(200);
        res.end();
        clearTimeout(timeout);
        server.close();
        if (token) {
          resolve({ token, expiresIn: expiresIn ? parseInt(expiresIn, 10) : null });
        } else {
          reject(new Error(`Login failed: ${error || 'unknown error'}`));
        }
        return;
      }

      res.writeHead(404);
      res.end();
    });

    server.listen(CALLBACK_PORT, 'localhost');
    server.on('error', (err) => reject(new Error(
      `Could not start callback server on port ${CALLBACK_PORT}: ${err.message}`,
    )));

    timeout = setTimeout(() => {
      server.close();
      reject(new Error('Login timed out. Please try again.'));
    }, timeoutMs);
  });
}

// ─── Login flow ──────────────────────────────────────────────────────────────

/**
 * Opens the browser for the IMS login flow and waits for the token.
 *
 * @param {object} [opts]
 * @param {Function} [opts.log=console.info] - Logger function (string => void).
 * @param {number}   [opts.timeoutMs]         - Forwarded to waitForToken.
 * @returns {Promise<string>} access token
 */
async function login({ log = console.info, timeoutMs } = {}) {
  const state = crypto.randomBytes(16).toString('hex');
  const params = new URLSearchParams({
    response_type: 'token',
    client_id: CLIENT_ID,
    scope: SCOPE,
    redirect_uri: REDIRECT_URI,
    state,
  });
  const authUrl = `${IMS_ORIGIN}/ims/authorize/v2?${params}`;

  log('Opening browser for da.live login…');
  log(`If the browser does not open automatically, visit:\n  ${authUrl}\n`);
  log('Waiting for login to complete…');

  // Start the callback server BEFORE opening the browser so the redirect
  // never races against server startup.
  const tokenPromise = waitForToken({ timeoutMs, expectedState: state });
  await open(authUrl);

  const { token, expiresIn } = await tokenPromise;

  await storeToken({
    access_token: token,
    expires_at: expiresIn ? Date.now() + (expiresIn * 1000) : null,
  });

  log(`Login successful. Token saved to ${TOKEN_FILE}`);
  return token;
}

// ─── Public API ──────────────────────────────────────────────────────────────

/**
 * Returns a valid da.live / IMS access token, triggering the browser login
 * flow only when necessary.
 *
 * Priority:
 *  1. Caller-supplied `override` token — used as-is, never persisted.
 *  2. Token cached in ~/.aem/da-token.json that has not expired yet.
 *  3. Full browser implicit OAuth flow (opens a tab, starts a local server).
 *
 * @param {object} [opts]
 * @param {string}   [opts.override]  - Hard-coded token (e.g. from env / CI).
 * @param {Function} [opts.log]       - Logger. Defaults to console.info.
 * @param {number}   [opts.timeoutMs] - Browser-flow timeout in ms (default 5 min).
 * @returns {Promise<string>} valid access token
 */
export async function getValidToken({ override, log = console.info, timeoutMs } = {}) {
  // 1. Explicit override (CI / automation / MCP server env var)
  if (override) return override;

  const stored = await loadStoredToken();

  // 2. Cached token still valid
  if (stored?.access_token && !isTokenExpired(stored)) {
    return stored.access_token;
  }

  if (stored?.access_token) {
    log('Stored token has expired. Re-authenticating…');
  }

  // 3. Full browser login
  return login({ log, timeoutMs });
}

/**
 * Clears the stored token, forcing a fresh login on the next getValidToken call.
 *
 * @returns {Promise<void>}
 */
export async function clearStoredToken() {
  if (await fse.pathExists(TOKEN_FILE)) {
    await fse.remove(TOKEN_FILE);
  }
}
