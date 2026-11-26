import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * Settings shared by playwright.real.config.ts and its sign-in setup. The credentials are
 * throwaway values made for this suite and only ever used against local test processes.
 */

const basePort = Number(process.env.REAL_STACK_PORT ?? '18381');
// The seeded lodeline-server, started by the ignored Rust test serve_seeded_proxies_until_killed.
export const SERVER_PORT = basePort;
export const CONSOLE_PORT = basePort + 1;
export const SERVER_URL = `http://127.0.0.1:${SERVER_PORT}`;
export const BASE_URL = `http://127.0.0.1:${CONSOLE_PORT}`;

// The read token the in-process server of src/fleet/tests.rs accepts.
export const READ_TOKEN = 'contract-read-token';
export const ADMIN_USERNAME = 'admin';
export const ADMIN_PASSWORD = 'test-password';
// Bcrypt hash of ADMIN_PASSWORD at cost 10.
export const ADMIN_PASSWORD_BCRYPT = '$2a$10$wfv94g2jgl.5WmoEZHXfw.WMQSDL6HzwEq0avcAT1QmtrqBWUf7wu';
export const JWT_SECRET = '0123456789abcdefghijklmnopqrstuv';

export const AUTH_STATE =
  process.env.REAL_STACK_AUTH_STATE ??
  fileURLToPath(new URL('../../.playwright/auth-real.json', import.meta.url));

// Workers load this module again and inherit the variable, so a run makes one directory.
if (process.env.REAL_STACK_RUN_DIR === undefined) {
  const dir = mkdtempSync(join(tmpdir(), 'lodeline-real-stack-'));
  process.env.REAL_STACK_RUN_DIR = dir;
  process.on('exit', () => rmSync(dir, { recursive: true, force: true }));
}
export const TRIAGE_DB_PATH = join(process.env.REAL_STACK_RUN_DIR, 'triage.sqlite');
