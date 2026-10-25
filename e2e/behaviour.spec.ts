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

test('the advanced panel counts joint outcomes and distinguishes a structural zero from sample noise', async ({ page }) => {
  await page.goto(`.${WORKING}`);
  const panel = page.locator('#advanced');
  await expect(panel.locator('.advanced-table').first().locator('tbody tr')).toHaveCount(3);
  await expect(panel.locator('.advanced-table').last().locator('tbody tr')).toHaveCount(4);
  await expect(panel.locator('.advanced-table').first().locator('tbody tr').last()).toContainText('128/256');
  await expect(panel).toContainText('full population, not a sample');

  await panel.locator('#advanced-samples').selectOption('16');
  await panel.locator('#advanced-key').selectOption('4660');
  await expect(panel).toContainText('finite sample may look biased');
  const total = await panel.locator('.advanced-table').last().locator('tbody td:last-child').allTextContents();
  expect(total.map(Number).reduce((sum, count) => sum + count, 0)).toBe(16);
  await expect(panel).toContainText('does not implement a full multidimensional key-recovery attack');
});

test('sampling comparison shows unique coverage and uncertainty while retaining the original curve', async ({ page }) => {
  await page.goto(`.${WORKING}&seed=3198`);
  await page.locator('#measure-compare').click();
  await expect(page.locator('#measure-result .curve tbody tr')).toHaveCount(4, { timeout: 180_000 });
  const fullCodebook = page.locator('#measure-result .curve tbody tr').last();
  await expect(fullCodebook).toContainText('256 / 256');
  await expect(page.locator('#measure-result')).toContainText('Wilson intervals');
  await expect(page.locator('#measure-result')).toContainText('not a guarantee for any key');
  await expect(page.locator('#measure-result a[href*="cambridge.org"]')).toBeVisible();
  await page.locator('#measure-run').click();
  await expect(page.locator('#measure-result .curve tbody tr')).toHaveCount(5, { timeout: 180_000 });
  await expect(page.locator('#measure-result')).toContainText("Matsui's single-counter prediction");
});

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

/* ── Exhibit 9: the differential–linear composition ──────────────────────── */

/**
 * The composition is fully deterministic — the pairs are fixed by the budget,
 * not sampled — so a pinned key pins the entire outcome. k = 14996 (0x3A94)
 * gives K4 = 0xA9 for the 3-round cipher; every asserted count below was
 * reproduced independently of the app before being pinned.
 */
const DL_WORKING = '?k=14996&dl=aligned&dlb=64';
const DL_CONTROL = '?k=14996&dl=cancelled&dlb=128';

test('the aligned composition recovers the last-round byte from chosen pairs', async ({ page }) => {
  await page.goto(`.${DL_WORKING}`);
  await page.locator('#dl-run').click();
  await expect(page.locator('#dl-verdict')).toHaveClass('verdict is-broken');
  await expect(page.locator('#dl-verdict')).toContainText('LAST-ROUND BYTE RECOVERED');
  await expect(page.locator('#dl-verdict')).toContainText('0xA9');
  const status = page.locator('#dl-status');
  await expect(status).toContainText('Ranking: 64 chosen pairs / 128 oracle queries');
  await expect(status).toContainText('Verification: 64 fresh pairs / 128 more queries');
  await expect(status).toContainText('Total: 256 oracle queries');
  const top = page.locator('#dl-ranking tbody tr').first();
  await expect(top).toContainText('0xA9');
  await expect(top.locator('.marker.is-pick')).toBeVisible();
  await expect(top.locator('.marker.is-key')).toBeVisible();
  // 50 of 64 pairs agreed under the winner — the pinned vector.
  await expect(top).toContainText('50 / 64');
});

test('the holdout verification confirms the winner on pairs the ranking never saw', async ({ page }) => {
  await page.goto(`.${DL_WORKING}`);
  await page.locator('#dl-run').click();
  await expect(page.locator('#dl-verdict')).toHaveClass('verdict is-broken');
  const holdout = page.locator('#dl-holdout');
  await expect(holdout).toContainText('64 fresh pairs');
  await expect(holdout).toContainText('54 / 64');
  await expect(holdout).toContainText('47 / 64');
  await expect(holdout).toContainText("preserve the winner's separation from every rival");
});

test('the composition names its pieces: the difference, the joining state, the masks', async ({ page }) => {
  await page.goto(`.${DL_WORKING}`);
  await expect(page.locator('label[for="dl-aligned"]')).toContainText('256 byte hypotheses');
  await expect(page.locator('label[for="dl-aligned"]')).not.toContainText('recovers the byte');
  const setup = page.locator('#dl-setup');
  await expect(setup).toContainText('ΔX = 0x0B');
  await expect(setup).toContainText('8 of 16');
  await expect(setup).toContainText('p = 1/2');
  await expect(setup).toContainText('ΔY = 0x08');
  await expect(setup).toContainText('entering round 2');
  await expect(setup).toContainText('−0.7500');
  await expect(setup).toContainText('ε = 3/8');
  await expect(setup).toContainText('always uses the Heys S-box');
  await expect(setup).toContainText('cockpit\'s S-box and round controls do not alter it');
  await expect(setup).toContainText('does not claim an attack on the full 4-round toy cipher');
});

test('the heuristic stack shows all three numbers, including the honest mismatch', async ({ page }) => {
  await page.goto(`.${DL_WORKING}`);
  await page.locator('#difflin details.deep').nth(1).locator('summary').click();
  const heuristics = page.locator('#dl-heuristics');
  await expect(heuristics).toContainText('Biham–Dunkelman–Keller p-weighted');
  await expect(heuristics).toContainText('2·p·ε²');
  await expect(heuristics).toContainText('+9/64');
  await expect(heuristics).toContainText('+9/32');
  await expect(heuristics).toContainText('+0.3125');
  await expect(heuristics).toContainText('understates');
});

test('the control measures exactly zero where the heuristic promised signal', async ({ page }) => {
  await page.goto(`.${DL_CONTROL}`);
  await page.locator('#dl-run').click();
  await expect(page.locator('#dl-verdict')).toHaveClass('verdict is-held');
  await expect(page.locator('#dl-verdict')).toContainText('NO SIGNAL — THE CONTROL');
  await expect(page.locator('#dl-verdict')).toContainText('ranks 16 high-nibble hypotheses');
  await expect(page.locator('#dl-verdict')).toContainText('0 times at 96 and 128 pairs');
  // The ranking ran and crowned noise: the top row is the pick, not the key.
  // The real key is still shown — appended at its true rank, marked, so the
  // learner can see how far down the control pushed it.
  const topRow = page.locator('#dl-ranking tbody tr').first();
  await expect(topRow.locator('.marker.is-pick')).toBeVisible();
  await expect(topRow.locator('.marker.is-pick')).toHaveText('largest |bias|');
  await expect(topRow.locator('.marker.is-key')).toHaveCount(0);
  await expect(page.locator('#dl-ranking .marker.is-key')).toHaveCount(1);
  const heuristicsPanel = page.locator('#difflin details.deep').nth(1).locator('summary');
  await heuristicsPanel.click();
  await expect(page.locator('#dl-heuristics')).toContainText('+1/16');
  await expect(page.locator('#dl-heuristics')).toContainText('signed path sum is 0');
  await expect(page.locator('#dl-heuristics')).toContainText('0.0000');
});

test('a finite-budget control separates exact cancellation from sample noise', async ({ page }) => {
  await page.goto('.?k=14996&dl=cancelled&dlb=32');
  await page.locator('#dl-run').click();
  const verdict = page.locator('#dl-verdict');
  await expect(verdict).toHaveClass('verdict is-held');
  await expect(verdict).toContainText('exact signed path sum is 0');
  await expect(verdict).toContainText('selected 32-pair run measures −0.1250');
  await expect(verdict).toContainText('finite-sample noise');
});

test('a starved budget produces an honest tie, not a quiet success', async ({ page }) => {
  await page.goto(`.?k=14996&dl=aligned&dlb=16`);
  await page.locator('#dl-run').click();
  await expect(page.locator('#dl-verdict')).toHaveClass('verdict is-partial');
  await expect(page.locator('#dl-verdict')).toContainText('TIED AT THE TOP');
});

test('a top tie includes the true byte even when numeric ordering lists another guess first', async ({ page }) => {
  await page.goto('.?k=5418&dl=aligned&dlb=16');
  await page.locator('#dl-run').click();
  await expect(page.locator('#dl-verdict')).toHaveClass('verdict is-partial');
  await expect(page.locator('#dl-verdict')).toContainText('TIED AT THE TOP');
  const first = page.locator('#dl-ranking tbody tr').first();
  await expect(first).toContainText('0x42');
  await expect(first.locator('.marker.is-pick')).toBeVisible();
  await expect(first.locator('.marker.is-key')).toHaveCount(0);
  await expect(page.locator('#dl-ranking .marker.is-key')).toHaveCount(1);
  await expect(page.locator('#dl-ranking .marker.is-key')).toHaveText('actual byte');
  const rows = page.locator('#dl-ranking tbody tr');
  await expect(rows.nth(0).locator('td').first()).toHaveText('1');
  await expect(rows.nth(1).locator('td').first()).toHaveText('1');
  await expect(rows.nth(2).locator('td').first()).toHaveText('1');
  await expect(rows.nth(3).locator('td').first()).toHaveText('4');
});

test('changing composition settings retires the previous ranking', async ({ page }) => {
  await page.goto(`.${DL_WORKING}`);
  await page.locator('#dl-run').click();
  await expect(page.locator('#dl-verdict')).toHaveClass('verdict is-broken');

  await page.click('label[for="dlb-16"]');
  await expect(page.locator('#dlb-16')).toBeChecked();
  await expect(page.locator('#dl-verdict')).toHaveClass('verdict is-stale');
  await expect(page.locator('#dl-status')).toHaveClass('run-status is-stale');
  await expect(page.locator('#dl-ranking .marker.is-key')).toHaveCount(0);
  await expect(page.locator('#dl-holdout')).toContainText('settings moved after this result');
  await expect(page.locator('#dl-holdout')).not.toContainText('budget of 128');

  await page.locator('#dl-run').click();
  await expect(page.locator('#dl-verdict')).not.toHaveClass('verdict is-stale');
  const rerunStatus = page.locator('#dl-status');
  await expect(rerunStatus).toContainText('Ranking: 16 chosen pairs / 32 oracle queries');
  await expect(rerunStatus).toContainText('Verification: 112 fresh pairs / 224 more queries');
  await expect(rerunStatus).toContainText('Total: 256 oracle queries');
});

test('composition controls update the URL and survive reload', async ({ page }) => {
  await page.goto(`.${DL_WORKING}`);
  await expect(page.locator('#dl-measure-run')).toHaveText('Measure the real success rate');
  await expect(page.locator('#dl-measure-status')).toBeEmpty();
  await page.click('label[for="dl-cancelled"]');
  await page.click('label[for="dlb-32"]');
  await expect(page.locator('#dl-measure-run')).toHaveText('Measure the real success rate');
  await expect(page.locator('#dl-measure-status')).toBeEmpty();
  await expect(page.locator('#dl-measure-result')).toBeEmpty();
  await expect.poll(() => new URL(page.url()).searchParams.get('dl')).toBe('cancelled');
  await expect.poll(() => new URL(page.url()).searchParams.get('dlb')).toBe('32');

  await page.reload();
  await expect(page.locator('#dl-cancelled')).toBeChecked();
  await expect(page.locator('#dlb-32')).toBeChecked();
});

test('the measured success rate is a deterministic curve over 512 keys', async ({ page }) => {
  await page.goto(`.${DL_WORKING}`);
  await page.locator('#dl-measure-run').click();
  await expect(page.locator('#dl-measure-cancel')).toBeVisible();
  await expect(page.locator('#dl-measure-result .dl-curve tbody tr')).toHaveCount(5, { timeout: 120_000 });
  const rows = page.locator('#dl-measure-result .dl-curve tbody tr');
  // The pinned deterministic curve over the stride-129 key walk:
  // A tie counts as partial recovery whenever the true byte is anywhere in
  // the top equivalence class, not only when numeric tie-breaking happens to
  // list it first. The cells are matched exactly so a sign error cannot hide
  // inside a substring.
  const rate = (row: number) => rows.nth(row).locator('td').nth(2);
  await expect(rate(0)).toHaveText('31.3%');
  await expect(rate(1)).toHaveText('66.8%');
  await expect(rate(2)).toHaveText('90.2%');
  await expect(rate(3)).toHaveText('99.8%');
  await expect(rate(4)).toHaveText('100.0%');
  await expect(page.locator('#dl-measure-status')).toContainText('2,560 complete rankings run');
});

test('changing the composition retires a completed or in-flight success curve', async ({ page }) => {
  await page.goto(`.${DL_WORKING}`);
  await page.locator('#dl-measure-run').click();
  await expect(page.locator('#dl-measure-result .dl-curve tbody tr')).toHaveCount(5, { timeout: 120_000 });
  await page.click('label[for="dl-cancelled"]');
  await expect(page.locator('#dl-measure-cancel')).toBeHidden();
  await expect(page.locator('#dl-measure-result')).toBeEmpty();
  await expect(page.locator('#dl-measure-status')).toContainText('prior measurement was retired');
  await expect(page.locator('#difflin .ranking-wrap')).toHaveAttribute(
    'aria-label',
    'The 16 observable last-round high-nibble hypotheses, ranked by absolute bias',
  );

  // Return to the slower 256-hypothesis design, then retire it in flight. Its
  // worker is terminated and its revision token prevents any already-queued
  // message from landing under the control.
  await page.click('label[for="dl-aligned"]');
  await page.locator('#dl-measure-run').click();
  await expect(page.locator('#dl-measure-cancel')).toBeVisible();
  await page.click('label[for="dl-cancelled"]');
  await expect(page.locator('#dl-measure-cancel')).toBeHidden();
  await expect(page.locator('#dl-measure-result')).toBeEmpty();
  await expect(page.locator('#dl-measure-status')).toContainText('prior measurement was retired');
});

test('a share link reproduces the exact composition', async ({ page }) => {
  await page.goto(`.?k=14996&dl=cancelled&dlb=96`);
  await expect(page.locator('#dl-cancelled')).toBeChecked();
  await expect(page.locator('#dlb-96')).toBeChecked();
  const url = page.url();
  expect(url).toContain('dl=cancelled');
  expect(url).toContain('dlb=96');
  await page.goto(url);
  await expect(page.locator('#dl-cancelled')).toBeChecked();
  await expect(page.locator('#dlb-96')).toBeChecked();
});
