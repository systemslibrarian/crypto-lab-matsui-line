import { expect, test, type Page } from '@playwright/test';

/**
 * Narrative and state-correctness tests — the things axe cannot check.
 *
 * Every scenario pins the key and the sampling seed through the URL, so a
 * failure here means the demo changed its story, not that a random draw went
 * the other way.
 */

/** k=0x3A94 with the whole codebook: the attack always names 0xA here. */
const WORKING = '?sbox=heys&rounds=3&half=high&n=codebook&approx=auto&k=14996';
/** k=0 at four rounds: the correct nibble ranks third, and must not be claimed. */
const FAILING = '?sbox=heys&rounds=4&half=high&n=codebook&approx=auto&k=0';

async function run(page: Page): Promise<void> {
  await page.locator('#attack-run').click();
  await expect(page.locator('#run-status')).toContainText('Counted', { timeout: 20_000 });
}

test('the default scenario recovers the expected key nibble', async ({ page }) => {
  await page.goto(`.${WORKING}`);
  await run(page);
  await expect(page.locator('#attack-verdict')).toContainText('KEY RECOVERED');
  await expect(page.locator('#attack-verdict')).toContainText('0xA');
  // The winning row is both the pick and the truth.
  const top = page.locator('#attack-ranking tbody tr').first();
  await expect(top).toContainText('0xA');
  await expect(top.locator('.marker.is-key')).toBeVisible();
  await expect(top.locator('.marker.is-pick')).toBeVisible();
});

test('a failed attack never marks a wrong guess as the key', async ({ page }) => {
  await page.goto(`.${FAILING}`);
  await run(page);
  await expect(page.locator('#attack-verdict')).not.toContainText('KEY RECOVERED');
  await expect(page.locator('#attack-verdict')).toContainText('NOT RECOVERED');
  // The top row is the attack's pick; the "actual key" badge must be elsewhere.
  const rows = page.locator('#attack-ranking tbody tr');
  await expect(rows.first().locator('.marker.is-pick')).toBeVisible();
  await expect(rows.first().locator('.marker.is-key')).toHaveCount(0);
  await expect(page.locator('#attack-ranking .marker.is-key')).toHaveCount(1);
});

test('starved data produces an honest inconclusive result, not a quiet success', async ({ page }) => {
  await page.goto(`.${WORKING}`);
  await page.locator('#preset-starve').click();
  await expect(page.locator('#run-status')).toContainText('Counted 16', { timeout: 20_000 });
  const verdict = page.locator('#attack-verdict');
  // Whatever 16 pairs happen to say, the page must report what it counted and
  // must not present a recovered key as certain without the evidence.
  await expect(verdict).toContainText(/KEY RECOVERED|NOT RECOVERED|PARTIAL/);
  if (await verdict.locator('text=KEY RECOVERED').count()) {
    await expect(verdict).toContainText('16 known plaintexts');
  }
});

test('changing configuration invalidates the previous result', async ({ page }) => {
  await page.goto(`.${WORKING}`);
  await run(page);
  await expect(page.locator('#attack-verdict')).toContainText('KEY RECOVERED');

  // Any outcome-affecting control must retire the result rather than leave it
  // sitting under settings that did not produce it.
  await page.locator('#seg-traffic label:has-text("64")').click();
  await expect(page.locator('#attack-verdict')).toContainText('CONFIGURATION CHANGED');
  await expect(page.locator('#run-status')).toContainText('run again');
  await expect(page.locator('#attack-ranking .marker.is-key')).toHaveCount(0);

  await run(page);
  await expect(page.locator('#attack-verdict')).not.toContainText('CONFIGURATION CHANGED');
  await expect(page.locator('#run-status')).toContainText('Counted 64');
});

test('the key stays hidden until the learner asks or the attack earns it', async ({ page }) => {
  await page.goto(`.${WORKING}`);
  await expect(page.locator('#key-value')).toHaveText('4 hidden bits');

  // Mid-count, the ranking must not label the answer.
  await page.locator('#attack-run').click();
  await expect(page.locator('#attack-verdict')).toContainText('COUNTING');
  await expect(page.locator('#attack-ranking .marker.is-key')).toHaveCount(0);
  await expect(page.locator('#run-status')).toContainText('Counted', { timeout: 20_000 });
  await expect(page.locator('#key-value')).toContainText('nibble recovered');

  await page.locator('#key-reveal').click();
  await expect(page.locator('#key-value')).toContainText('0x3A94');
});

test('an experiment link reproduces the same ranking', async ({ page }) => {
  await page.goto(`.${WORKING}&seed=12345&n=1024`);
  await run(page);
  const first = await page.locator('#attack-ranking tbody').innerText();
  const url = page.url();
  expect(url).toContain('seed=12345');

  await page.goto(url);
  await run(page);
  expect(await page.locator('#attack-ranking tbody').innerText()).toBe(first);
});

test('the primary action is in the first viewport and keyboard reachable', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto('.');
  const box = await page.locator('#attack-run').boundingBox();
  expect(box).not.toBeNull();
  expect(box!.y).toBeLessThan(900);

  // Reachable by keyboard without a mouse: tab until it has focus.
  await page.keyboard.press('Tab');
  for (let i = 0; i < 40; i++) {
    if (await page.locator('#attack-run').evaluate((el) => el === document.activeElement)) break;
    await page.keyboard.press('Tab');
  }
  await expect(page.locator('#attack-run')).toBeFocused();
  await page.keyboard.press('Enter');
  await expect(page.locator('#run-status')).toContainText('Counted', { timeout: 20_000 });
});

test('reduced motion reaches the same final state without the counting animation', async ({ browser }) => {
  const context = await browser.newContext({ reducedMotion: 'reduce' });
  const page = await context.newPage();
  await page.goto(`.${WORKING}`);
  await page.locator('#attack-run').click();
  // No intermediate counting state: the result is there immediately.
  await expect(page.locator('#attack-verdict')).toContainText('KEY RECOVERED', { timeout: 5_000 });
  await expect(page.locator('#attack-verdict')).toContainText('0xA');
  await context.close();
});

for (const width of [320, 390, 768, 1440]) {
  test(`no horizontal overflow at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await page.goto(`.${WORKING}`);
    await run(page);
    const overflow = await page.evaluate(
      () => document.documentElement.scrollWidth > document.documentElement.clientWidth + 1,
    );
    expect(overflow).toBe(false);
  });
}

test('the mechanism chain reports the values of the run that just happened', async ({ page }) => {
  await page.goto(`.${WORKING}`);
  await expect(page.locator('#mechanism-chain')).toContainText('not run yet');
  await run(page);
  await expect(page.locator('#mechanism-chain')).toContainText('256 pairs counted');
  await expect(page.locator('#mechanism-chain')).toContainText('ε = +1/8');
});

test('a hopeless approximation is rejected or visibly finds nothing', async ({ page }) => {
  await page.goto(`.${WORKING}`);
  await page.locator('#preset-bad').click();
  await expect(page.locator('#approx-readout')).toContainText('predicted bias 0');
  await expect(page.locator('#run-status')).toContainText('Counted', { timeout: 20_000 });
  await expect(page.locator('#attack-verdict')).not.toContainText('KEY RECOVERED');
});
