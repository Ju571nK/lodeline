import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { defineConfig, devices } from '@playwright/test';

/**
 * Playwright runs e2e specs against the **production binary** with the
 * embedded SPA, not the Vite dev server. That way we exercise the same
 * routing + cookie semantics + middleware that ship.
 *
 * Before running, the harness expects:
 *   - the binary at `MANAGER_BIN`, or a release build at
 *     `../target/release/lodeline-manager` made after `npm run build`,
 *   - `MOCK_FLEET=1` so no live lodeline-server is needed,
 *   - the env vars below (which match `.env.example`).
 *
 * Tests share one server instance. Its triage DB is `E2E_TRIAGE_DB_PATH`, or
 * a file in a temp dir made for this run and removed when it ends, so each
 * `npx playwright test` run starts clean and parallel runs do not share it.
 *
 * The console allows 10 login attempts a minute per client address, and
 * every test connects from 127.0.0.1. So the `setup` project signs in once
 * and saves the session cookie to `AUTH_STATE`, which every test starts
 * with. Tests of the login page itself start without it. A run makes 5
 * logins from 127.0.0.1 (setup, the organization sign-in spec's local
 * sign-in, and the login spec's valid, wrong password and logout tests).
 * Adding more than 5 login attempts would hit the limit.
 */

function newRunDb(): string {
  const dir = mkdtempSync(join(tmpdir(), 'lodeline-manager-e2e-'));
  process.on('exit', () => rmSync(dir, { recursive: true, force: true }));
  return join(dir, 'triage.sqlite');
}
// Workers load this config again and inherit the variable, so a run makes one dir.
const TRIAGE_DB_PATH = process.env.E2E_TRIAGE_DB_PATH ?? newRunDb();
process.env.E2E_TRIAGE_DB_PATH = TRIAGE_DB_PATH;

export const AUTH_STATE =
  process.env.E2E_AUTH_STATE ?? fileURLToPath(new URL('.playwright/auth.json', import.meta.url));

const PORT = process.env.PORT ?? '18181';
const BASE_URL = `http://localhost:${PORT}`;

// Bcrypt hash of "test-password" at cost 10.
const TEST_ADMIN_HASH = '$2a$10$wfv94g2jgl.5WmoEZHXfw.WMQSDL6HzwEq0avcAT1QmtrqBWUf7wu';

export default defineConfig({
  testDir: './tests/e2e',
  fullyParallel: false, // single backend instance = serial tests
  workers: 1,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [['github'], ['list'], ['html', { open: 'never' }]] : 'list',

  use: {
    baseURL: BASE_URL,
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    actionTimeout: 5_000,
    navigationTimeout: 10_000,
  },

  webServer: {
    command: process.env.MANAGER_BIN ?? '../target/release/lodeline-manager',
    url: `${BASE_URL}/api/health`,
    reuseExistingServer: !process.env.CI,
    timeout: 30_000,
    env: {
      LISTEN_ADDR: `:${PORT}`,
      MOCK_FLEET: '1',
      TRIAGE_DB_PATH,
      ADMIN_USERNAME: 'admin',
      ADMIN_PASSWORD_BCRYPT: TEST_ADMIN_HASH,
      JWT_SECRET: '0123456789abcdefghijklmnopqrstuv',
      LODELINE_INSECURE_COOKIE: '1',
    },
  },

  projects: [
    { name: 'setup', testMatch: /auth\.setup\.ts/ },
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'], storageState: AUTH_STATE },
      dependencies: ['setup'],
    },
  ],
});
