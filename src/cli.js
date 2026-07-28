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

/**
 * Minimal CLI entrypoint.
 *
 * Commands:
 *   da-auth-helper login    — alias for token
 *   da-auth-helper logout   — clear the cached token
 *   da-auth-helper token    — print the current token (login if needed)
 */

import { getValidToken, clearStoredToken } from './auth.js';

const [, , command = 'token'] = process.argv;

const log = (msg) => process.stderr.write(`${msg}\n`);

try {
  switch (command) {
    case 'login':
    case 'token': {
      const token = await getValidToken({ log });
      process.stdout.write(`${token}\n`);
      break;
    }
    case 'logout': {
      await clearStoredToken();
      log('Stored token cleared.');
      break;
    }
    default:
      log(`Unknown command: ${command}`);
      log('Usage: da-auth-helper [login|logout|token]');
      process.exit(1);
  }
} catch (err) {
  log(`Error: ${err.message}`);
  process.exit(1);
}
