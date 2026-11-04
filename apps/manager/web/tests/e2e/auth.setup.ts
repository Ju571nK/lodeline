import { expect, test as setup } from '@playwright/test';
import { AUTH_STATE } from '../../playwright.config';

setup('sign in once for the run', async ({ request }) => {
  const res = await request.post('/api/v1/auth/login', {
    data: { username: 'admin', password: 'test-password' },
  });
  expect(res.status()).toBe(200);
  await request.storageState({ path: AUTH_STATE });
});
