import { expect, test as setup } from '@playwright/test';
import { ADMIN_PASSWORD, ADMIN_USERNAME, AUTH_STATE } from './env';

setup('sign in once for the run', async ({ request }) => {
  const res = await request.post('/api/v1/auth/login', {
    data: { username: ADMIN_USERNAME, password: ADMIN_PASSWORD },
  });
  expect(res.status()).toBe(200);
  await request.storageState({ path: AUTH_STATE });
});
