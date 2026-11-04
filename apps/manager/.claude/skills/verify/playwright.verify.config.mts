import base from '../../../web/playwright.config';

const outputDir = process.env.LODELINE_VERIFY_OUTPUT;
if (!outputDir) throw new Error('Run this config through drive.sh e2e');

// webServer stays off so a dead instance fails the run. The base config would
// boot a second server with its own SQLite file instead.
export default {
  ...base,
  testDir: '../../../web/tests/e2e',
  outputDir,
  reporter: 'list',
  webServer: undefined,
  use: { ...base.use, trace: 'on', screenshot: 'on' },
};
