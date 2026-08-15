import { expect, test } from '@playwright/test';
import { expectNotBlank, settle } from './gate';

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
 *
 * Flake control asks for reduced motion the way a reader does —
 * `emulateMedia({ reducedMotion: 'reduce' })` — instead of injecting
 * `animation:none; transition:none` through `addStyleTag`, which is what this
 * spec used to do. The injection BYPASSED this lab's own
 * `@media (prefers-reduced-motion: reduce)` block instead of exercising it, so
 * a broken reduced-motion path could never be observed here. Now these shots
 * ARE the reduced-motion rendering: if that block ever stops delivering end
 * states (say, by switching from `animation-duration: 0.001ms` to
 * `animation: none` on something that animates in), the blankness check and
 * the screenshot both fail.
 *
 * Two details are load-bearing, both documented at length in `gate.ts`:
 *
 *  - The emulation must precede `goto`, because `main.ts` reads
 *    `matchMedia('(prefers-reduced-motion: reduce)').matches` ONCE at module
 *    scope and branches on it (the counters advance in one call instead of
 *    over 45 frames; preset scrolls are instant).
 *  - The preference is asserted from inside the page rather than assumed,
 *    because `test.use({ reducedMotion })` silently does nothing on
 *    Playwright 1.61.1 and a silent no-op would put this suite back on a
 *    rendering nobody is served — without saying so.
 */

const WORKING = '?sbox=heys&rounds=3&half=high&n=codebook&approx=auto&k=14996&seed=7';
const FAILING = '?sbox=heys&rounds=4&half=high&n=codebook&approx=auto&k=0&seed=7';

for (const theme of ['dark'] as const) {
  test(`cockpit after a successful break — ${theme}`, async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 1100 });
    await page.emulateMedia({ reducedMotion: 'reduce' });
    await page.goto(`.${WORKING}`);
    expect(
      await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
      'reduced-motion emulation must actually be in effect'
    ).toBe(true);
    await page.locator('#attack-run').click();
    await expect(page.locator('#run-status')).toContainText('Counted', { timeout: 20_000 });
    // The run's animated-in content must actually arrive under reduced motion:
    // sixteen filled ranking bars and a verdict, not sixteen `.is-empty` stubs.
    await expect(page.locator('#attack-ranking tbody .rank-bar')).toHaveCount(16);
    await expect(page.locator('#attack-ranking .rank-bar.is-empty')).toHaveCount(0);
    await expect(page.locator('#attack-verdict')).toContainText('KEY RECOVERED');
    await settle(page);
    await expectNotBlank(page, `${theme} cockpit after a successful break`);
    await expect(page.locator('#attack')).toHaveScreenshot(`cockpit-break-${theme}.png`, {
      maxDiffPixelRatio: 0.01,
    });
  });

  test(`cockpit after a failed attack — ${theme}`, async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 1100 });
    await page.emulateMedia({ reducedMotion: 'reduce' });
    await page.goto(`.${FAILING}`);
    expect(
      await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
      'reduced-motion emulation must actually be in effect'
    ).toBe(true);
    await page.locator('#attack-run').click();
    await expect(page.locator('#run-status')).toContainText('Counted', { timeout: 20_000 });
    await expect(page.locator('#attack-ranking tbody .rank-bar')).toHaveCount(16);
    await expect(page.locator('#attack-ranking .rank-bar.is-empty')).toHaveCount(0);
    await expect(page.locator('#attack-verdict')).toContainText('NOT RECOVERED');
    await settle(page);
    await expectNotBlank(page, `${theme} cockpit after a failed attack`);
    await expect(page.locator('#attack')).toHaveScreenshot(`cockpit-fail-${theme}.png`, {
      maxDiffPixelRatio: 0.01,
    });
  });
}
