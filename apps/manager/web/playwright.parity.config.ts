import { defineConfig } from '@playwright/test';
import * as env from './tests/parity/env.ts';

/**
 * Parity recorder: `npm run parity` (see tests/parity/README.md). It runs
 * only with this config, so `npx playwright test` keeps running the e2e
 * suite alone. Two manager processes start from the same binary as the e2e
 * config: one on the mock fleet, one reading a stub upstream.
 */

const MANAGER_BIN = process.env.MANAGER_BIN ?? '../target/release/lodeline-manager';

function managerEnv(port: number, extra: Record<string, string>): Record<string, string> {
  return {
    LISTEN_ADDR: `127.0.0.1:${port}`,
    // Go's /auth/me formats the token expiry in the process time zone.
    TZ: 'UTC',
    ADMIN_USERNAME: env.ADMIN_USERNAME,
    ADMIN_PASSWORD_BCRYPT: env.ADMIN_PASSWORD_BCRYPT,
    JWT_SECRET: env.JWT_SECRET,
    JWT_TTL_HOURS: String(env.JWT_TTL_HOURS),
    OIDC_ISSUER_URL: '',
    OIDC_CLIENT_ID: '',
    OIDC_CLIENT_SECRET: '',
    OIDC_REDIRECT_URL: '',
    OIDC_ALLOWED_SUBJECTS: '',
    ...extra,
  };
}

export default defineConfig({
  testDir: './tests/parity',
  testMatch: 'run.parity.ts',
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: 'list',
  projects: [{ name: 'parity' }],
  webServer: [
    {
      command: 'node tests/parity/stub-upstream.mjs',
      url: `${env.STUB_URL}/__stub/health`,
      reuseExistingServer: false,
      env: { PARITY_STUB_PORT: String(env.STUB_PORT) },
    },
    {
      command: MANAGER_BIN,
      url: `${env.MOCK_URL}/api/health`,
      reuseExistingServer: false,
      timeout: 30_000,
      stderr: 'ignore',
      env: managerEnv(env.MOCK_PORT, {
        MOCK_FLEET: '1',
        TRIAGE_DB_PATH: env.MOCK_DB,
        LODELINE_INSECURE_COOKIE: '1',
      }),
    },
    {
      command: MANAGER_BIN,
      url: `${env.LIVE_URL}/api/health`,
      reuseExistingServer: false,
      timeout: 30_000,
      stderr: 'ignore',
      env: managerEnv(env.LIVE_PORT, {
        MOCK_FLEET: '0',
        LODELINE_SERVER_BASE_URL: env.STUB_URL,
        LODELINE_SERVER_READ_TOKEN: env.READ_TOKEN,
        FLEET_CACHE_DISABLED: '1',
        TRIAGE_DB_PATH: env.LIVE_DB,
        LODELINE_INSECURE_COOKIE: '0',
      }),
    },
  ],
});
