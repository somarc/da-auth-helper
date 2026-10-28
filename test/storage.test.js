import { jest } from '@jest/globals';
import fs from 'fs/promises';
import os from 'os';
import path from 'path';

import {
  clearStoredToken,
  loadStoredToken,
  storeToken,
} from '../src/storage.js';

let temporaryHome;
let tokenFile;

beforeEach(async () => {
  temporaryHome = await fs.mkdtemp(path.join(os.tmpdir(), 'da-auth-helper-'));
  tokenFile = path.join(temporaryHome, '.aem', 'da-token.json');
});

afterEach(async () => {
  await fs.rm(temporaryHome, { recursive: true, force: true });
});

describe('secure token storage', () => {
  test('creates a 0700 directory and atomically installs a 0600 token file', async () => {
    await storeToken({ access_token: 'TOKEN', expires_at: 123456789 }, tokenFile);

    const directoryStats = await fs.lstat(path.dirname(tokenFile));
    const fileStats = await fs.lstat(tokenFile);
    expect(directoryStats.mode & 0o777).toBe(0o700);
    expect(fileStats.mode & 0o777).toBe(0o600);
    expect(fileStats.nlink).toBe(1);
    await expect(loadStoredToken(tokenFile)).resolves.toEqual({
      access_token: 'TOKEN',
      expires_at: 123456789,
    });

    const entries = await fs.readdir(path.dirname(tokenFile));
    expect(entries).toEqual(['da-token.json']);
  });

  test('repairs legacy directory and file modes before reading', async () => {
    await fs.mkdir(path.dirname(tokenFile), { recursive: true, mode: 0o755 });
    await fs.chmod(path.dirname(tokenFile), 0o755);
    await fs.writeFile(tokenFile, JSON.stringify({
      access_token: 'LEGACY',
      expires_at: 123456789,
    }), { mode: 0o644 });
    await fs.chmod(tokenFile, 0o644);

    await expect(loadStoredToken(tokenFile)).resolves.toMatchObject({ access_token: 'LEGACY' });
    expect((await fs.lstat(path.dirname(tokenFile))).mode & 0o777).toBe(0o700);
    expect((await fs.lstat(tokenFile)).mode & 0o777).toBe(0o600);
  });

  test('treats malformed JSON as a cache miss after validating the file', async () => {
    await fs.mkdir(path.dirname(tokenFile), { recursive: true, mode: 0o700 });
    await fs.writeFile(tokenFile, '{not-json', { mode: 0o600 });
    await expect(loadStoredToken(tokenFile)).resolves.toBeNull();
  });

  test('leaves the old credential intact and removes the temp file when rename fails', async () => {
    await storeToken({ access_token: 'OLD', expires_at: 123456789 }, tokenFile);
    const rename = jest.fn(async () => {
      throw Object.assign(new Error('simulated rename failure'), { code: 'EIO' });
    });

    await expect(storeToken(
      { access_token: 'NEW', expires_at: 223456789 },
      tokenFile,
      { fsImpl: { ...fs, rename }, randomBytes: () => Buffer.alloc(12, 0xab) },
    )).rejects.toThrow('credential could not be stored safely');

    await expect(loadStoredToken(tokenFile)).resolves.toMatchObject({ access_token: 'OLD' });
    expect(await fs.readdir(path.dirname(tokenFile))).toEqual(['da-token.json']);
  });

  test('does not report rollback after rename has committed the new credential', async () => {
    await storeToken({ access_token: 'OLD', expires_at: 123456789 }, tokenFile);
    let renamed = false;
    const fsImpl = {
      ...fs,
      async rename(from, to) {
        await fs.rename(from, to);
        renamed = true;
      },
      async open(target, ...args) {
        const handle = await fs.open(target, ...args);
        if (renamed && target === path.dirname(tokenFile)) {
          return {
            async sync() {
              throw Object.assign(new Error('simulated directory fsync failure'), { code: 'EIO' });
            },
            close: () => handle.close(),
          };
        }
        return handle;
      },
    };

    await expect(storeToken(
      { access_token: 'NEW', expires_at: 223456789 },
      tokenFile,
      { fsImpl },
    )).resolves.toBeUndefined();
    await expect(loadStoredToken(tokenFile)).resolves.toMatchObject({ access_token: 'NEW' });
  });

  test('rejects a symlink credential rather than following it', async () => {
    const outside = path.join(temporaryHome, 'outside.json');
    await fs.mkdir(path.dirname(tokenFile), { recursive: true, mode: 0o700 });
    await fs.writeFile(outside, JSON.stringify({ access_token: 'OUTSIDE', expires_at: 1 }), {
      mode: 0o600,
    });
    await fs.symlink(outside, tokenFile);

    await expect(loadStoredToken(tokenFile)).rejects.toThrow('regular file, not a link');
    await expect(storeToken(
      { access_token: 'NEW', expires_at: 123456789 },
      tokenFile,
    )).rejects.toThrow('regular file, not a link');
    expect(JSON.parse(await fs.readFile(outside, 'utf8')).access_token).toBe('OUTSIDE');
  });

  test('rejects a symlink credential directory', async () => {
    const outsideDirectory = path.join(temporaryHome, 'outside');
    await fs.mkdir(outsideDirectory, { mode: 0o700 });
    await fs.symlink(outsideDirectory, path.dirname(tokenFile));

    await expect(storeToken(
      { access_token: 'NEW', expires_at: 123456789 },
      tokenFile,
    )).rejects.toThrow('real directory, not a link');
  });

  test('rejects a multiply linked credential file', async () => {
    await fs.mkdir(path.dirname(tokenFile), { recursive: true, mode: 0o700 });
    await fs.writeFile(tokenFile, JSON.stringify({ access_token: 'TOKEN', expires_at: 1 }), {
      mode: 0o600,
    });
    await fs.link(tokenFile, path.join(temporaryHome, 'second-link.json'));

    await expect(loadStoredToken(tokenFile)).rejects.toThrow('must not have additional hard links');
  });

  test('rejects invalid candidate data before creating a credential directory', async () => {
    await expect(storeToken({ access_token: '', expires_at: null }, tokenFile))
      .rejects.toThrow('invalid access token');
    await expect(fs.lstat(path.dirname(tokenFile))).rejects.toMatchObject({ code: 'ENOENT' });
  });

  test('removes a validated credential and leaves no token file', async () => {
    await storeToken({ access_token: 'TOKEN', expires_at: 123456789 }, tokenFile);
    await clearStoredToken(tokenFile);
    await expect(fs.lstat(tokenFile)).rejects.toMatchObject({ code: 'ENOENT' });
    await expect(clearStoredToken(tokenFile)).resolves.toBeUndefined();
  });

  test('refuses to clear a symlink target', async () => {
    const outside = path.join(temporaryHome, 'outside.json');
    await fs.mkdir(path.dirname(tokenFile), { recursive: true, mode: 0o700 });
    await fs.writeFile(outside, 'keep', { mode: 0o600 });
    await fs.symlink(outside, tokenFile);

    await expect(clearStoredToken(tokenFile)).rejects.toThrow('regular file, not a link');
    await expect(fs.readFile(outside, 'utf8')).resolves.toBe('keep');
  });
});
