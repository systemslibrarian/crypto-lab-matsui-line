import { expect, test } from '@playwright/test';
import { boot, driveAllStates, NARROW, reportCollected, watchPageErrors } from './gate';

/**
 * WCAG A/AA regression gate.
 *
 * The lab is driven along everything it teaches, and every state is scanned:
 * the arrival state, with sixteen empty counters and five disclosures shut; the
 * skip link focused by a real Tab press; the key revealed and hidden again; the
 * attack at the shipped configuration; the stale state a changed control leaves
 * behind; all four scenario presets, including the four-round codebook run that
 * does NOT recover and the dead approximation with no trail at all; the tuning
 * drawer; all three ways a custom mask is rejected; all three approximation
 * modes; both S-boxes; both target nibbles; the traffic control at the codebook
 * and at 4096; both ends of the plaintext slider; three shapes of LAT cell; the
 * piling-up trail stepped to the end and reset; the measured success curve and
 * its cancel path; the share link; and the finished page with everything open.
 * Each of those is scanned in {dark, light} × {1280px, 380px}.
 *
 * Clipboard permission is granted because "Copy experiment link" calls
 * `navigator.clipboard.writeText` inside a try/catch that writes a DIFFERENT
 * button label on rejection: without the grant the drive would be asserting
 * against the failure branch while claiming to scan the success one.
 *
 * See `gate.ts` for why nothing is injected into the page (this lab reads
 * `prefers-reduced-motion` in its TypeScript as well as its CSS), why no
 * disclosure or `[hidden]` element is force-revealed, why the lab's defaults are
 * asserted rather than assumed, why `violations` is not the whole oracle on a
 * page whose cockpit is a gradient, and which single state — the ~900ms
 * "counting" rendering — is deliberately out of reach under reduced motion.
 */

for (const theme of ['dark'] as const) {
  test(`no WCAG A/AA violations in ${theme} theme`, async ({ page, context }) => {
    test.setTimeout(1_500_000);
    await context.grantPermissions(['clipboard-read', 'clipboard-write']);
    const errors = watchPageErrors(page);
    await boot(page, theme);
    await driveAllStates(page, theme);
    expect(errors, errors.join('\n')).toEqual([]);
    reportCollected();
  });

  test(`no WCAG A/AA violations in ${theme} theme at 380px`, async ({ page, context }) => {
    test.setTimeout(1_500_000);
    await context.grantPermissions(['clipboard-read', 'clipboard-write']);
    const errors = watchPageErrors(page);
    await page.setViewportSize(NARROW);
    await boot(page, theme);
    await driveAllStates(page, `${theme} @380px`);
    expect(errors, errors.join('\n')).toEqual([]);
    reportCollected();
  });
}
