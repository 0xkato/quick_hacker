import { test, expect } from '@playwright/test';

test('quick clone fixture repo and render call tree', async ({ page }) => {
  const fixtureCloneUrl =
    process.env.E2E_FIXTURE_CLONE_URL || '/app/tests/fixtures/generated_fastapi_repo';

  await page.goto('/');

  const exitButton = page.locator('button[title="Exit project"]');
  if (await exitButton.isVisible().catch(() => false)) {
    await exitButton.click();
  }

  await expect(page.getByText('Projects')).toBeVisible();

  await page.getByTestId('project-quick-clone').click();
  await page.getByTestId('quick-clone-url').fill(fixtureCloneUrl);
  await page.getByTestId('quick-clone-submit').click();

  await expect(page.getByTestId('ws-connection-status')).toContainText('Connected', {
    timeout: 60_000,
  });

  await page.locator('button[title="Investigation Flow"]').click();
  await page.getByTestId('diagram-mode-select').selectOption('calltree');

  const routeSelect = page.getByTestId('calltree-route-select');
  await expect(routeSelect).toBeEnabled();

  await expect
    .poll(async () => routeSelect.locator('option').count(), { timeout: 30_000 })
    .toBeGreaterThan(1);

  await routeSelect.selectOption({ index: 1 });

  await expect(page.getByText('GET /hello')).toBeVisible({ timeout: 60_000 });
  await expect(page.getByText('hello()')).toBeVisible();
});

