import { expect, test } from '@playwright/test';

/**
 * Visual regression, run locally via `npm run test:visual` — NOT part of the
 * deploy gate.
 *
 * Playwright names baselines per platform, and text rendering differs enough
 * between macOS and the Linux CI runner that a committed macOS baseline would
 * fail on CI for reasons that have nothing to do with the change under review.
 * Gating a deploy on that would train everyone to ignore the gate. The
 * accessibility and behaviour suites are the ones that gate.
 *
 * Both shots are pinned to a fixed key and seed so a diff means the rendering
 * moved, not the experiment.
 */

const WORKING = '?sbox=heys&rounds=3&half=high&n=codebook&approx=auto&k=14996&seed=7';
const FAILING = '?sbox=heys&rounds=4&half=high&n=codebook&approx=auto&k=0&seed=7';

for (const theme of ['dark', 'light'] as const) {
  test(`cockpit after a successful break — ${theme}`, async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 1100 });
    await page.goto(`.${WORKING}`);
    if (theme === 'light') {
      await page.locator('#cl-theme-toggle').click();
      await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
    }
    await page.locator('#attack-run').click();
    await expect(page.locator('#run-status')).toContainText('Counted', { timeout: 20_000 });
    await page.addStyleTag({ content: '*,*::before,*::after{animation:none!important;transition:none!important}' });
    await expect(page.locator('#attack')).toHaveScreenshot(`cockpit-break-${theme}.png`, {
      maxDiffPixelRatio: 0.01,
    });
  });

  test(`cockpit after a failed attack — ${theme}`, async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 1100 });
    await page.goto(`.${FAILING}`);
    if (theme === 'light') {
      await page.locator('#cl-theme-toggle').click();
      await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
    }
    await page.locator('#attack-run').click();
    await expect(page.locator('#run-status')).toContainText('Counted', { timeout: 20_000 });
    await page.addStyleTag({ content: '*,*::before,*::after{animation:none!important;transition:none!important}' });
    await expect(page.locator('#attack')).toHaveScreenshot(`cockpit-fail-${theme}.png`, {
      maxDiffPixelRatio: 0.01,
    });
  });
}
