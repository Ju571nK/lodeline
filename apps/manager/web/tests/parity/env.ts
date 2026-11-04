import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

/**
 * Settings shared by playwright.parity.config.ts and the recorder. The
 * credentials are throwaway values made for this suite and only ever used
 * against local test processes.
 */

export const ADMIN_USERNAME = process.env.PARITY_ADMIN_USERNAME ?? 'admin';
export const ADMIN_PASSWORD = 'parity-9866c8cb59b2029c';
// Bcrypt (cost 10, $2y$ prefix) of ADMIN_PASSWORD.
export const ADMIN_PASSWORD_BCRYPT = '$2y$10$qZuItXlc/MfSA/5vLEKM9uK1tXFuGeLTf6QTheNacl.CkQHYW.AbK';
export const JWT_SECRET = 'parity-jwt-29d7b42591a19bb0ac7e84f4b0b4169b38028f60';
// Ten years, so the session token kept in testdata/ stays valid for later phases.
export const JWT_TTL_HOURS = 87600;
export const READ_TOKEN = 'parity-read-d2931eaa245b0ba9';

const basePort = Number(process.env.PARITY_PORT ?? '18281');
export const MOCK_PORT = basePort;
export const LIVE_PORT = basePort + 1;
export const STUB_PORT = basePort + 2;
export const MOCK_URL = `http://127.0.0.1:${MOCK_PORT}`;
export const LIVE_URL = `http://127.0.0.1:${LIVE_PORT}`;
export const STUB_URL = `http://127.0.0.1:${STUB_PORT}`;

// Write goldens or testdata. Only for recording against the Go reference; CI never sets these.
export const UPDATE = process.env.PARITY_UPDATE === '1';
export const WRITE_TESTDATA = process.env.PARITY_TESTDATA === '1';
export const ALLOW_ANY_REFERENCE = process.env.PARITY_ALLOW_ANY_REFERENCE === '1';

// The config process sets these first; test workers inherit them, so every
// process agrees on one run directory and one run start.
if (process.env.PARITY_RUN_DIR === undefined) {
  const dir = mkdtempSync(join(tmpdir(), 'lodeline-parity-'));
  process.env.PARITY_RUN_DIR = dir;
  process.on('exit', () => rmSync(dir, { recursive: true, force: true }));
}
process.env.PARITY_RUN_START ??= String(Date.now());
export const RUN_DIR = process.env.PARITY_RUN_DIR;
export const RUN_START_MS = Number(process.env.PARITY_RUN_START);
export const MOCK_DB = join(RUN_DIR, 'triage.sqlite');
export const LIVE_DB = join(RUN_DIR, 'triage-live.sqlite');
