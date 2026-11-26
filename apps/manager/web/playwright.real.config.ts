import { defineConfig, devices } from '@playwright/test';
import * as env from './tests/e2e-real/env.ts';

/**
 * Real-stack run: `npm run e2e:real` (see tests/e2e-real/README.md). The console binary reads a
 * real lodeline-server over HTTP, not the mock fleet. Two processes start in order:
 *
 *   1. the seeded server: the ignored Rust test serve_seeded_proxies_until_killed, which seeds
 *      the registry, the status reports, the invocations and the inventory of the contract
 *      test and serves them on SERVER_PORT until it is stopped,
 *   2. the console binary at MANAGER_BIN, or a release build at
 *      `../target/release/lodeline-manager` made after `npm run build`, pointed at it.
 *
 * The seed times are relative to the server start, so a proxy reads as connected only for
 * about a minute. Specs that read connection state go first, and the console starts straight
 * after the server.
 */

const MANAGER_BIN = process.env.MANAGER_BIN ?? '../target/release/lodeline-manager';

export default defineConfig({
  testDir: './tests/e2e-real',
  testMatch: /.*\.(spec|setup)\.ts/,
  outputDir: 'test-results/real',
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: 'list',

  use: {
    baseURL: env.BASE_URL,
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    actionTimeout: 5_000,
    navigationTimeout: 10_000,
  },

  webServer: [
    {
      // The first run compiles the console's test build, so the wait is long.
      command: 'cargo +1.100.0 test serve_seeded_proxies_until_killed -- --ignored --nocapture',
      cwd: '..',
      port: env.SERVER_PORT,
      reuseExistingServer: false,
      timeout: 600_000,
      stdout: 'ignore',
      gracefulShutdown: { signal: 'SIGTERM', timeout: 10_000 },
      env: { PXRLS_PORT: String(env.SERVER_PORT) },
    },
    {
      command: MANAGER_BIN,
      url: `${env.BASE_URL}/api/health`,
      reuseExistingServer: false,
      timeout: 30_000,
      stdout: 'ignore',
      stderr: 'ignore',
      gracefulShutdown: { signal: 'SIGTERM', timeout: 5_000 },
      env: {
        LISTEN_ADDR: `127.0.0.1:${env.CONSOLE_PORT}`,
        LODELINE_SERVER_BASE_URL: env.SERVER_URL,
        LODELINE_SERVER_READ_TOKEN: env.READ_TOKEN,
        TRIAGE_DB_PATH: env.TRIAGE_DB_PATH,
        ADMIN_USERNAME: env.ADMIN_USERNAME,
        ADMIN_PASSWORD_BCRYPT: env.ADMIN_PASSWORD_BCRYPT,
        JWT_SECRET: env.JWT_SECRET,
        LODELINE_INSECURE_COOKIE: '1',
      },
    },
  ],

  projects: [
    { name: 'setup', testMatch: /auth\.setup\.ts/ },
    {
      name: 'real-stack',
      testMatch: /.*\.spec\.ts/,
      use: { ...devices['Desktop Chrome'], storageState: env.AUTH_STATE },
      dependencies: ['setup'],
    },
  ],
});
