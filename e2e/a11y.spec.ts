import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/**
 * Axe only checks what is in the DOM, so an unscanned state is an ungated
 * state. This walks every exhibit into the states a visitor can actually
 * reach — including the two failure verdicts, which is exactly where a
 * contrast slip would hide — before anything is scanned.
 */
async function driveDemos(page: Page): Promise<void> {
  // Exhibit 1 — cipher walkthrough, both S-boxes, key revealed.
  await page.locator('#plaintext-input').fill('183');
  await page.locator('#key-reveal').click();
  await expect(page.locator('#key-reveal')).toHaveAttribute('aria-pressed', 'true');
  await page.locator('#key-new').click();

  // Exhibit 2 — LAT: a leaking cell, a balanced cell, and a trivial cell.
  for (const [a, b] of [
    [11, 4],
    [1, 1],
    [0, 3],
    [9, 8],
  ]) {
    await page.locator(`.lat-cell[data-a="${a}"][data-b="${b}"]`).click();
    await expect(page.locator('#lat-detail h3')).toBeVisible();
  }

  // Exhibit 3 — step the piling-up trail all the way to the end, then reset
  // and step once so both the pending and applied cards are on screen.
  for (let i = 0; i < 4; i++) {
    const step = page.locator('#piling-step');
    if (await step.isEnabled()) await step.click();
  }
  await page.locator('#piling-reset').click();
  await page.locator('#piling-step').click();

  // Exhibit 4 — the attack, in all three verdict states.
  await page.locator('#attack-codebook').click(); // recovered → alarm styling
  await expect(page.locator('#attack-verdict')).toContainText(/RECOVERED|PARTIAL|NOT RUN/);
  await page.locator('#samples-input').fill('4'); // 16 pairs: too thin to work
  await page.locator('#attack-run').click();

  // The custom-mask path, including its rejection state.
  await page.locator('#approx-select').selectOption('custom');
  await page.locator('#mask-end').fill('193'); // straddles both nibbles → rejected
  await expect(page.locator('#attack-run')).toBeDisabled();
  await page.locator('#mask-end').fill('192');
  await expect(page.locator('#attack-run')).toBeEnabled();
  await page.locator('#attack-run').click();
  await page.locator('#approx-select').selectOption('ranked');
  await page.locator('#approx-select').selectOption('auto');

  // Exhibit 5 — the measured success curve (a real computation, not a mock).
  await page.locator('#measure-run').click();
  await expect(page.locator('#measure-result table')).toBeVisible({ timeout: 60_000 });

  // The full cipher, where the attack is supposed to fail, plus the S-box swap
  // and the nibble that resists — three more result states to scan.
  await page.locator('#rounds-select').selectOption('4');
  await page.locator('#attack-codebook').click();
  await page.locator('#half-select').selectOption('low');
  await page.locator('#attack-codebook').click();
  await page.locator('#sbox-select').selectOption('present');
  await page.locator('#attack-codebook').click();
  await page.locator('#rounds-select').selectOption('3');
  await page.locator('#half-select').selectOption('high');
  await page.locator('#sbox-select').selectOption('heys');
  await page.locator('#attack-codebook').click();
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
