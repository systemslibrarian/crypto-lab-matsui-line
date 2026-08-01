import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/**
 * Axe only checks what is in the DOM, so an unscanned state is an ungated
 * state. This walks every exhibit into the states a visitor can actually
 * reach — including the two failure verdicts, which is exactly where a
 * contrast slip would hide — before anything is scanned.
 */
const pick = (page: Page, group: string, label: string) =>
  page.locator(`#seg-${group} label`, { hasText: label }).first().click();

const finished = (page: Page) =>
  expect(page.locator('#run-status')).toContainText(/Counted|run again|cannot/, { timeout: 30_000 });

async function driveDemos(page: Page): Promise<void> {
  // Exhibit 1 — the cockpit, in each of its states: idle is already on screen,
  // then counting, then done, then stale, then blocked.
  await page.locator('#attack-run').click();
  await finished(page);
  await expect(page.locator('#attack-verdict')).toContainText(/RECOVERED|PARTIAL/);
  await page.locator('#key-reveal').click();
  await expect(page.locator('#key-reveal')).toHaveAttribute('aria-pressed', 'true');

  // Every scenario preset, each of which lands in a different verdict.
  await page.locator('#preset-starve').click();
  await finished(page);
  await page.locator('#preset-round').click();
  await finished(page);
  await page.locator('#preset-bad').click();
  await finished(page);
  await page.locator('#preset-reset').click();
  await finished(page);

  // The rejected-approximation state (a mask straddling both nibbles).
  await page.locator('details.tune > summary').click();
  await pick(page, 'approx', 'My own masks');
  await page.locator('#mask-end').fill('193');
  await expect(page.locator('#attack-run')).toBeDisabled();
  await page.locator('#mask-end').fill('192');
  await expect(page.locator('#attack-run')).toBeEnabled();
  await page.locator('#attack-run').click();
  await finished(page);
  await pick(page, 'approx', 'Strongest, unverified');
  await pick(page, 'approx', 'Verified');

  // The stale state needs a result to retire first, so run, then change a
  // control and leave the retired result on screen to be scanned.
  await page.locator('#attack-run').click();
  await finished(page);
  await pick(page, 'traffic', '256');
  await expect(page.locator('#attack-verdict')).toContainText('CONFIGURATION CHANGED');
  await page.locator('#attack-run').click();
  await finished(page);
  await page.locator('#key-new').click();

  // Exhibit 3 — cipher walkthrough.
  await page.locator('#plaintext-input').fill('183');

  // Exhibit 4 — LAT: a leaking cell, a balanced cell, and a trivial cell.
  for (const [a, b] of [
    [11, 4],
    [1, 1],
    [0, 3],
    [9, 8],
  ]) {
    await page.locator(`.lat-cell[data-a="${a}"][data-b="${b}"]`).click();
    await expect(page.locator('#lat-detail h3')).toBeVisible();
  }

  // Exhibit 5 — step the trail to the end, then reset and step once so both
  // the applied and pending cards get scanned.
  for (let i = 0; i < 4; i++) {
    const step = page.locator('#piling-step');
    if (await step.isEnabled()) await step.click();
  }
  await page.locator('#piling-reset').click();
  await page.locator('#piling-step').click();

  // Exhibit 6 — the measured success curve, off-thread, with its progress bar.
  await page.locator('#measure-run').click();
  await expect(page.locator('#measure-result table')).toBeVisible({ timeout: 120_000 });

  // The S-box swap and the nibble that resists — two more result states.
  await pick(page, 'sbox', 'PRESENT');
  await page.locator('#attack-run').click();
  await finished(page);
  await pick(page, 'half', 'Low');
  await pick(page, 'sbox', 'Heys');
  await page.locator('#attack-run').click();
  await finished(page);
}

async function prepare(page: Page): Promise<void> {
  await page.addStyleTag({
    content: `*,*::before,*::after{animation:none!important;transition:none!important}`,
  });
  await page.evaluate(() => {
    document.querySelectorAll('details').forEach((d) => ((d as HTMLDetailsElement).open = true));
    document.querySelectorAll<HTMLElement>('[hidden],[role="tabpanel"]').forEach((el) => {
      el.removeAttribute('hidden');
      el.style.display = '';
      el.classList.add('active', 'is-active', 'open');
    });
  });
  await page.waitForTimeout(400);
}

async function scan(page: Page): Promise<void> {
  const { violations } = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  expect(
    violations.map((v) => ({
      id: v.id,
      impact: v.impact,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
    })),
  ).toEqual([]);
}

test('no WCAG A/AA violations — dark theme', async ({ page }) => {
  await page.goto('.');
  await driveDemos(page);
  await prepare(page);
  await scan(page);
});

test('no WCAG A/AA violations — light theme', async ({ page }) => {
  await page.goto('.');
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await driveDemos(page);
  await prepare(page);
  await scan(page);
});

test('no WCAG A/AA violations — narrow viewport, both themes', async ({ page }) => {
  // The layout stacks below 640px; stacked is a different rendering, so it is
  // a different scan.
  await page.setViewportSize({ width: 380, height: 900 });
  await page.goto('.');
  await driveDemos(page);
  await prepare(page);
  await scan(page);
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await prepare(page);
  await scan(page);
});
