#!/usr/bin/env node
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

import path from 'path';
import { pathToFileURL } from 'url';
import {
  AUTH_EVENT_SCHEMA,
  AuthError,
  acquireToken,
  clearStoredToken,
  getValidToken,
} from './auth.js';

const USAGE = `Usage:
  da-auth-helper token [--reauthenticate] [--no-open] [--timeout-ms <ms>] [--events=ndjson]
  da-auth-helper login [--reauthenticate] [--no-open] [--timeout-ms <ms>] [--events=ndjson]
  da-auth-helper acquire [--reauthenticate] [--no-open] [--timeout-ms <ms>] [--events=ndjson]
  da-auth-helper logout

Commands:
  token     Return a cached token or acquire and store a replacement (default).
  login     Alias for token; use --reauthenticate to require a fresh IMS login.
  acquire   Acquire a fresh caller-owned token without reading or writing the cache.
  logout    Remove the default cached token.

The token is the only stdout value. Status and versioned token-free events use stderr.`;

function invalidArgument(message) {
  return new AuthError('INVALID_ARGUMENT', message);
}

export function parseArgs(argv) {
  const args = [...argv];
  let command = 'token';
  if (args[0] && !args[0].startsWith('-')) command = args.shift();

  if (!['token', 'login', 'acquire', 'logout'].includes(command)) {
    throw invalidArgument(`Unknown command: ${command}`);
  }

  const options = {
    reauthenticate: false,
    openBrowser: true,
    timeoutMs: undefined,
    events: 'human',
    help: false,
  };

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === '--help' || arg === '-h') {
      options.help = true;
    } else if (arg === '--reauthenticate') {
      options.reauthenticate = true;
    } else if (arg === '--no-open') {
      options.openBrowser = false;
    } else if (arg === '--events=ndjson') {
      options.events = 'ndjson';
    } else if (arg === '--events') {
      const value = args[index + 1];
      if (value !== 'ndjson') throw invalidArgument('--events must be ndjson.');
      options.events = value;
      index += 1;
    } else if (arg === '--timeout-ms') {
      const value = args[index + 1];
      if (!value || !/^\d+$/.test(value)) {
        throw invalidArgument('--timeout-ms requires a positive integer.');
      }
      options.timeoutMs = Number(value);
      index += 1;
    } else {
      throw invalidArgument(`Unknown option: ${arg}`);
    }
  }

  if (command === 'logout'
    && (options.reauthenticate
      || !options.openBrowser
      || options.timeoutMs !== undefined
      || options.events !== 'human')) {
    throw invalidArgument('logout does not accept authentication options.');
  }

  return { command, ...options };
}

function writeStream(stream, text) {
  return new Promise((resolve, reject) => {
    try {
      if (typeof stream?.write !== 'function') {
        reject(new Error('output stream is unavailable'));
        return;
      }
      if (stream.write.length >= 2) {
        stream.write(text, (error) => {
          if (error) reject(error);
          else resolve();
        });
      } else {
        stream.write(text);
        resolve();
      }
    } catch (error) {
      reject(error);
    }
  });
}

function eventLine(event) {
  return `${JSON.stringify(event)}\n`;
}

function humanEventLine(event) {
  switch (event.event) {
    case 'authorization_url':
      return `Authorization URL:\n  ${event.url}\n`;
    case 'waiting':
      return `Waiting for authorization (${Math.ceil(event.remainingMs / 1000)}s remaining)…\n`;
    case 'callback_rejected':
      return `Ignored callback (${event.code}); still waiting for the matching IMS response.\n`;
    case 'completed':
      return event.persisted
        ? 'Authorization received and stored.\n'
        : 'Authorization candidate received; the caller owns final persistence.\n';
    default:
      return '';
  }
}

function publicError(error) {
  if (error instanceof AuthError) return error;
  return new AuthError('AUTH_FAILED', 'Authentication failed.');
}

async function reportError(stderr, error, ndjson) {
  const safe = publicError(error);
  const text = ndjson
    ? eventLine({
      schema: AUTH_EVENT_SCHEMA,
      event: 'error',
      code: safe.code,
      retryable: safe.retryable,
      message: safe.message,
    })
    : `Error [${safe.code}]: ${safe.message}\n`;
  try {
    await writeStream(stderr, text);
  } catch {
    // There is no safe secondary output channel if stderr itself failed.
  }
}

/**
 * Testable CLI runner. It returns an exit code and never calls process.exit().
 */
export async function runCli({
  argv = process.argv.slice(2),
  stdout = process.stdout,
  stderr = process.stderr,
  signal,
  auth = { acquireToken, clearStoredToken, getValidToken },
} = {}) {
  const ndjsonRequested = argv.includes('--events=ndjson')
    || argv.some((arg, index) => arg === '--events' && argv[index + 1] === 'ndjson');

  try {
    const parsed = parseArgs(argv);
    if (parsed.help) {
      await writeStream(stderr, `${USAGE}\n`);
      return 0;
    }

    if (parsed.command === 'logout') {
      await auth.clearStoredToken();
      await writeStream(stderr, 'Stored token cleared.\n');
      return 0;
    }

    const onEvent = parsed.events === 'ndjson' || parsed.command === 'acquire'
      ? async (event) => {
        const line = parsed.events === 'ndjson' ? eventLine(event) : humanEventLine(event);
        if (line) await writeStream(stderr, line);
      }
      : undefined;

    const common = {
      reauthenticate: parsed.reauthenticate,
      openBrowser: parsed.openBrowser,
      signal,
      onEvent,
      ...(parsed.timeoutMs === undefined ? {} : { timeoutMs: parsed.timeoutMs }),
    };

    let token;
    if (parsed.command === 'acquire') {
      ({ token } = await auth.acquireToken(common));
    } else {
      token = await auth.getValidToken({
        ...common,
        log: parsed.events === 'ndjson'
          ? () => {}
          : (message) => stderr.write(`${message}\n`),
      });
    }

    await writeStream(stdout, `${token}\n`);
    return 0;
  } catch (error) {
    await reportError(stderr, error, ndjsonRequested);
    return 1;
  }
}

async function main() {
  const controller = new AbortController();
  const cancel = () => controller.abort();
  process.once('SIGINT', cancel);
  process.once('SIGTERM', cancel);
  try {
    process.exitCode = await runCli({ signal: controller.signal });
  } finally {
    process.removeListener('SIGINT', cancel);
    process.removeListener('SIGTERM', cancel);
  }
}

const invokedPath = process.argv[1] ? pathToFileURL(path.resolve(process.argv[1])).href : null;
if (invokedPath === import.meta.url) {
  await main();
}
