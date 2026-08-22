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

import crypto from 'crypto';
import { constants as FS_CONSTANTS } from 'fs';
import fs from 'fs/promises';
import os from 'os';
import path from 'path';

export const TOKEN_FILE = path.join(os.homedir(), '.aem', 'da-token.json');

const MAX_TOKEN_BYTES = 64 * 1024;
const MAX_TOKEN_FILE_BYTES = 128 * 1024;

class CredentialStoreError extends Error {
  constructor(message, { cause } = {}) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = 'CredentialStoreError';
  }
}

function storeError(message, cause) {
  return new CredentialStoreError(message, { cause });
}

async function lstatIfPresent(target, fsImpl) {
  try {
    return await fsImpl.lstat(target);
  } catch (error) {
    if (error?.code === 'ENOENT') return null;
    throw error;
  }
}

function assertOwned(stats, label) {
  if (typeof process.getuid === 'function' && stats.uid !== process.getuid()) {
    throw storeError(`${label} is not owned by the current user.`);
  }
}

function assertSecureDirectory(stats) {
  if (stats.isSymbolicLink() || !stats.isDirectory()) {
    throw storeError('The credential directory must be a real directory, not a link.');
  }
  assertOwned(stats, 'The credential directory');
}

function assertSecureFile(stats) {
  if (stats.isSymbolicLink() || !stats.isFile()) {
    throw storeError('The credential path must be a regular file, not a link.');
  }
  if (stats.nlink !== 1) {
    throw storeError('The credential file must not have additional hard links.');
  }
  assertOwned(stats, 'The credential file');
}

async function secureDirectory(directory, fsImpl) {
  let stats = await lstatIfPresent(directory, fsImpl);
  if (!stats) {
    await fsImpl.mkdir(directory, { recursive: true, mode: 0o700 });
    stats = await fsImpl.lstat(directory);
  }
  assertSecureDirectory(stats);

  if ((stats.mode & 0o777) !== 0o700) {
    await fsImpl.chmod(directory, 0o700);
    stats = await fsImpl.lstat(directory);
    assertSecureDirectory(stats);
    if ((stats.mode & 0o777) !== 0o700) {
      throw storeError('The credential directory permissions could not be secured.');
    }
  }
  return stats;
}

async function inspectExistingToken(tokenFile, fsImpl, { repairMode }) {
  let stats = await lstatIfPresent(tokenFile, fsImpl);
  if (!stats) return null;
  assertSecureFile(stats);

  if ((stats.mode & 0o777) !== 0o600 && repairMode) {
    await fsImpl.chmod(tokenFile, 0o600);
    stats = await fsImpl.lstat(tokenFile);
    assertSecureFile(stats);
  }
  if ((stats.mode & 0o777) !== 0o600) {
    throw storeError('The credential file permissions are not private.');
  }
  return stats;
}

function noFollowFlags(base) {
  return FS_CONSTANTS.O_NOFOLLOW === undefined ? base : base | FS_CONSTANTS.O_NOFOLLOW;
}

async function openVerifiedToken(tokenFile, expected, fsImpl) {
  const handle = await fsImpl.open(tokenFile, noFollowFlags(FS_CONSTANTS.O_RDONLY));
  try {
    const opened = await handle.stat();
    assertSecureFile(opened);
    if (opened.dev !== expected.dev || opened.ino !== expected.ino) {
      throw storeError('The credential file changed while it was being opened.');
    }
    if (opened.size > MAX_TOKEN_FILE_BYTES) {
      throw storeError('The credential file is unexpectedly large.');
    }
    return await handle.readFile('utf8');
  } finally {
    await handle.close();
  }
}

async function syncDirectory(directory, fsImpl) {
  let handle;
  try {
    handle = await fsImpl.open(directory, FS_CONSTANTS.O_RDONLY);
    await handle.sync();
  } catch (error) {
    // Some non-POSIX filesystems do not allow fsync on a directory. File
    // durability and atomic rename still apply there.
    if (!['EINVAL', 'ENOTSUP', 'EISDIR'].includes(error?.code)) throw error;
  } finally {
    await handle?.close();
  }
}

function serializeToken(tokenData) {
  if (!tokenData || typeof tokenData !== 'object') {
    throw storeError('Credential data must be an object.');
  }
  const { access_token: token, expires_at: expiresAt } = tokenData;
  if (typeof token !== 'string' || token.length === 0
    || Buffer.byteLength(token, 'utf8') > MAX_TOKEN_BYTES) {
    throw storeError('Credential data contains an invalid access token.');
  }
  if (expiresAt !== null
    && (!Number.isSafeInteger(expiresAt) || expiresAt <= 0)) {
    throw storeError('Credential data contains an invalid expiry.');
  }
  return `${JSON.stringify({ access_token: token, expires_at: expiresAt }, null, 2)}\n`;
}

/**
 * Reads a secure cached token. Malformed JSON is treated as a cache miss, while
 * unsafe filesystem objects fail closed.
 */
export async function loadStoredToken(tokenFile = TOKEN_FILE, { fsImpl = fs } = {}) {
  try {
    const stats = await lstatIfPresent(tokenFile, fsImpl);
    if (!stats) return null;
    await secureDirectory(path.dirname(tokenFile), fsImpl);
    const secured = await inspectExistingToken(tokenFile, fsImpl, { repairMode: true });
    const contents = await openVerifiedToken(tokenFile, secured, fsImpl);
    try {
      return JSON.parse(contents);
    } catch {
      return null;
    }
  } catch (cause) {
    if (cause instanceof CredentialStoreError) throw cause;
    throw storeError('The credential cache could not be read safely.', cause);
  }
}

/**
 * Writes a token through an exclusive 0600 same-directory temporary file and
 * atomic rename. The old credential remains intact until rename succeeds.
 */
export async function storeToken(tokenData, tokenFile = TOKEN_FILE, {
  fsImpl = fs,
  randomBytes = crypto.randomBytes,
} = {}) {
  const serialized = serializeToken(tokenData);
  const directory = path.dirname(tokenFile);
  const basename = path.basename(tokenFile);
  let temporaryFile;
  let handle;
  let renamed = false;

  try {
    await secureDirectory(directory, fsImpl);
    await inspectExistingToken(tokenFile, fsImpl, { repairMode: true });

    const suffix = randomBytes(12).toString('hex');
    temporaryFile = path.join(directory, `.${basename}.${process.pid}.${suffix}.tmp`);
    const flags = noFollowFlags(FS_CONSTANTS.O_WRONLY | FS_CONSTANTS.O_CREAT | FS_CONSTANTS.O_EXCL);
    handle = await fsImpl.open(temporaryFile, flags, 0o600);
    await handle.writeFile(serialized, 'utf8');
    await handle.sync();
    await handle.chmod(0o600);
    await handle.close();
    handle = undefined;

    await fsImpl.rename(temporaryFile, tokenFile);
    renamed = true;
    await fsImpl.chmod(tokenFile, 0o600);
    const stored = await fsImpl.lstat(tokenFile);
    assertSecureFile(stored);
    if ((stored.mode & 0o777) !== 0o600) {
      throw storeError('The credential file permissions could not be secured.');
    }
    await syncDirectory(directory, fsImpl);
  } catch (cause) {
    if (cause instanceof CredentialStoreError) throw cause;
    throw storeError('The credential could not be stored safely.', cause);
  } finally {
    await handle?.close().catch(() => {});
    if (temporaryFile && !renamed) {
      await fsImpl.unlink(temporaryFile).catch(() => {});
    }
  }
}

/** Removes the default cached token after validating the path is not a link. */
export async function clearStoredToken(tokenFile = TOKEN_FILE, { fsImpl = fs } = {}) {
  try {
    const stats = await lstatIfPresent(tokenFile, fsImpl);
    if (!stats) return;
    await secureDirectory(path.dirname(tokenFile), fsImpl);
    await inspectExistingToken(tokenFile, fsImpl, { repairMode: true });
    await fsImpl.unlink(tokenFile);
    await syncDirectory(path.dirname(tokenFile), fsImpl);
  } catch (cause) {
    if (cause instanceof CredentialStoreError) throw cause;
    throw storeError('The credential cache could not be cleared safely.', cause);
  }
}
