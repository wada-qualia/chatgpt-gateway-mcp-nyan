import { expect, test } from '@playwright/test';

test('gateway dashboard renders core navigation', async ({ page }) => {
  await page.goto('/');
  await expect(page.locator('body')).toContainText(/Gateway|ChatGPT|Thin Clients|Docker|Monitoring/i);
  await expect(page).toHaveScreenshot('gateway-dashboard.png', { fullPage: true, animations: 'disabled' });
});
