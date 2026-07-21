import { expect, test } from '@playwright/test';

test('changes and persists the interface language from Settings', async ({ page }) => {
  let settings = {
    ui_language: 'en',
    ssh_command_profile: 'unrestricted',
    ssh_command_profile_override: null,
    ssh_command_profile_default: 'unrestricted',
    raw_commands_enabled: true,
    deny_patterns_enabled: false
  };

  await page.route('**/auth/me', async (route) => {
    await route.fulfill({
      contentType: 'application/json',
      body: JSON.stringify({
        subject: 'dev:local',
        username: 'darius',
        email: 'dev@k-lab.local',
        roles: [],
        provider: 'keycloak'
      })
    });
  });
  await page.route('**/api/**', async (route) => {
    const pathname = new URL(route.request().url()).pathname;
    if (pathname === '/api/account/settings' || pathname === '/api/docker/images') {
      await route.fallback();
      return;
    }
    await route.fulfill({ contentType: 'application/json', body: '[]' });
  });
  await page.route('**/api/account/settings', async (route) => {
    if (route.request().method() === 'PATCH') {
      settings = { ...settings, ...(route.request().postDataJSON() as Partial<typeof settings>) };
    }
    await route.fulfill({ contentType: 'application/json', body: JSON.stringify(settings) });
  });
  await page.route('**/api/docker/images', async (route) => {
    await route.fulfill({ contentType: 'application/json', body: JSON.stringify({ images: ['ubuntu:24.04'] }) });
  });

  await page.goto('/settings');
  const language = page.getByRole('combobox', { name: 'Language' });
  await expect(language).toHaveValue('en');
  await language.selectOption('ru');

  await expect(page.getByRole('heading', { name: 'Настройки' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Устройства', exact: true })).toBeVisible();
  await expect(page.locator('html')).toHaveAttribute('lang', 'ru');
  await expect.poll(() => settings.ui_language).toBe('ru');

  await page.reload();
  await expect(page.getByRole('combobox', { name: 'Язык' })).toHaveValue('ru');
  await expect(page.getByRole('heading', { name: 'Настройки' })).toBeVisible();
});
