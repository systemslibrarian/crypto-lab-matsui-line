import AxeBuilder from '@axe-core/playwright';
import { expect, type Page } from '@playwright/test';
import { auditContrast, formatContrastFailures } from './contrast';
import { auditNonText, formatNonTextFailures } from './nontext';

export const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/** A phone-width viewport, for the WCAG 1.4.10 reflow half of the gate. */
export const NARROW = { width: 380, height: 800 };

/**
 * Shared machinery for the WCAG gate.
 *
 * Five rules govern everything here, each one a correction of the gate this
 * replaces:
 *
 *  1. NOTHING IS INJECTED INTO THE PAGE BEFORE A SCAN. `prepare()` pushed
 *     `animation:none!important; transition:none!important` through
 *     `addStyleTag`. That BYPASSED this stylesheet's own
 *     `@media (prefers-reduced-motion: reduce)` block instead of exercising it,
 *     so the block was never measured once — and on this page the preference
 *     reaches the TypeScript as well as the CSS. `main.ts` reads
 *     `matchMedia('(prefers-reduced-motion: reduce)').matches` at module scope
 *     and branches on it three times: `runAttackAnimated` advances all sixteen
 *     counters in one call instead of over 45 animation frames, `applyPreset`
 *     scrolls with `behavior: 'auto'` instead of `'smooth'`, and the attack's
 *     "counting" phase is skipped entirely. A style tag reaches none of that.
 *
 *     The reduced-motion block was checked for the defect where cancelling an
 *     animation strands an element at its start value. It cannot be in that
 *     shape: it sets `animation-duration` and `transition-duration` to
 *     0.001ms — it never sets `animation: none` — so every animation still runs
 *     and still ENDS at its end state. `expectNotBlank` measures the outcome in
 *     every state rather than trusting that reading.
 *
 *  2. IT FORCE-REVEALED EVERYTHING. `prepare()` set `open = true` on all five
 *     `<details>`, then stripped `hidden` from every `[hidden]` element, wiped
 *     their inline `display`, and added `active is-active open` to each — a
 *     document with `#custom-masks` and `#measure-cancel` both showing, which
 *     no visitor can ever produce and which no assertion described. It even
 *     targeted `[role="tabpanel"]`, of which this page has none: the helper was
 *     a fleet-wide template, not a description of this lab. This gate never
 *     touches `open`, `hidden` or `display`; `.tune` is opened by clicking its
 *     summary and `#custom-masks` appears because the Approximation control was
 *     switched to "My own masks".
 *
 *  3. IT SCANNED FOUR TIMES, AFTER THE DRIVE, WITH THE PAGE FORCED OPEN. Every
 *     state `driveDemos()` built — the starved run, the four-round run, the
 *     rejected approximation, the stale result, the PRESENT S-box — was
 *     replaced by the next one before anything was scanned, so a dozen distinct
 *     renderings were constructed and thrown away unmeasured. The narrow test
 *     was worse: it drove the page at 380px, scanned, then toggled the theme and
 *     scanned again WITHOUT re-driving, so the light-theme narrow scan measured
 *     whatever the dark drive happened to leave behind. This drive scans after
 *     every step, in {dark, light} × {1280, 380}.
 *
 *  4. `violations` IS NOT THE WHOLE ORACLE. See `scan`. On this page the gap is
 *     concrete: `.cockpit` — the box around the attack, its sixteen counters and
 *     its verdict — paints a `linear-gradient`, and axe declines to resolve a
 *     gradient, so a violations-only assertion measured the contrast of nothing
 *     in the first screen of the page.
 *
 *  5. IT HAD NO REFLOW, KEYBOARD-SCROLLER, FOCUS-INDICATOR OR 1.4.11 ORACLE AT
 *     ALL, and this page needs every one of them: eleven `overflow-x: auto`
 *     boxes, five of them `tabindex="0"` regions that are not `a`, `button`,
 *     `input`, `select` or `textarea`, and a 16x16 table of 256 buttons.
 *
 * ONE STATE IS DELIBERATELY OUT OF REACH, and it is named rather than faked:
 * `verdict is-counting` / `run-status is-counting`, the ~900ms rendering while
 * the counters fill. `runAttackAnimated` skips it outright when reduced motion
 * is set, so it is not a state any reader with the preference can see, and the
 * only way to scan it would be to lie to the page about the preference.
 */
/**
 * Wait for every running animation and transition to drain.
 *
 * Transitions drain in waves, not in one batch, so a poll for "nothing running
 * right now" can exit through a gap between waves. Require quiescence to hold
 * for several consecutive frames instead.
 */
export async function settle(page: Page): Promise<void> {
  await page.waitForFunction(
    () => {
      const w = window as unknown as { __quietFrames?: number };
      const running = document.getAnimations().filter((a) => a.playState === 'running');
      w.__quietFrames = running.length === 0 ? (w.__quietFrames ?? 0) + 1 : 0;
      return w.__quietFrames >= 6;
    },
    undefined,
    { timeout: 20_000, polling: 'raf' }
  );
}

/**
 * Assert that reduced motion left the page visible, not merely un-animated.
 *
 * The failure mode this guards against is an element whose only route to its
 * visible state is an animation, in a stylesheet whose reduced-motion block
 * cancels that animation without restoring its end state — the element then
 * renders at `opacity: 0` for every reader with the preference set.
 *
 * This page cannot currently be in that shape, and the assertion is what makes
 * that a measurement rather than a reading: its reduced-motion block sets
 * `animation-duration: 0.001ms` and `transition-duration: 0.001ms` — it never
 * sets `animation: none` — so every animation still runs and still arrives at
 * its end state. The one declared `opacity: 0` in the stylesheet is
 * `.seg-input`, the visually-hidden radio behind each segmented control, which
 * owns no text of its own. Both are properties of the current stylesheet rather
 * than of the page, which is why this runs in every state instead of being
 * reasoned about once.
 *
 * `aria-hidden` subtrees are excluded, since text removed from the
 * accessibility tree is not what this check is for. Inside `#app` the only such
 * text is the `.verdict-icon` and `.run-status-icon` glyphs, each of which sits
 * beside the word carrying the same meaning, in the same ink on the same
 * surface.
 */
async function expectNotBlank(page: Page, label: string): Promise<void> {
  const invisible = await page.evaluate(() => {
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll('body *'))) {
      const own = Array.from(el.childNodes)
        .filter((n) => n.nodeType === Node.TEXT_NODE)
        .map((n) => n.textContent ?? '')
        .join('')
        .trim();
      if (!own) continue;
      // Deliberately hidden subtrees are not "blank", they are closed.
      if (!(el as HTMLElement).checkVisibility?.({ checkVisibilityCSS: true })) continue;
      if (el.closest('[aria-hidden="true"]')) continue;
      let effective = 1;
      let node: Element | null = el;
      while (node) {
        effective *= parseFloat(getComputedStyle(node).opacity);
        node = node.parentElement;
      }
      if (effective === 0) {
        out.push(`${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}`);
      }
    }
    return Array.from(new Set(out));
  });
  expect(invisible, `no visible text may render at opacity 0 in state: ${label}`).toEqual([]);
}

/**
 * Uncaught page errors and console errors, collected from the moment the page
 * is created. A renderer that throws halfway through leaves an earlier state on
 * screen, and a gate that scans that state reports green for a page that is
 * broken. Attach before `boot`, assert after the drive.
 *
 * This matters more than usual here. `main.ts` resolves every element through a
 * `$()` that THROWS on a miss, and one of this page's exhibits runs in a module
 * `Worker` whose failure path is a silent `onerror` fallback to the main
 * thread — so a broken worker produces a correct-looking curve and a console
 * error, and nothing else. This is what notices.
 */
export function watchPageErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`));
  page.on('console', (m) => {
    if (m.type() === 'error') errors.push(`console.error: ${m.text()}`);
  });
  return errors;
}

/**
 * Exactly one banner landmark: the shared bar.
 *
 * The OUTCOME is asserted rather than either mechanism, so a change to the
 * nesting is caught as well as a change to the script. `index.html`'s
 * `dedupeBanner()` would demote a second banner to `role="group"`, but it never
 * fires here: this lab's `<header class="cl-hero">` sits inside
 * `<main id="app">`, which scopes it out of the banner role on its own, and
 * `dedupeBanner` returns early for exactly that case
 * (`el.closest('main, article, aside, nav, section')`). The single banner is
 * therefore a property of the markup, and this asserts it as one.
 */
export async function assertSingleBanner(page: Page): Promise<void> {
  const banners = await page.evaluate(() => {
    const scoped = new Set(['MAIN', 'ARTICLE', 'ASIDE', 'NAV', 'SECTION']);
    const isBanner = (el: Element): boolean => {
      if (el.getAttribute('role') === 'banner') return true;
      if (el.tagName !== 'HEADER') return false;
      if (el.getAttribute('role')) return false; // explicit non-banner role wins
      for (let p = el.parentElement; p; p = p.parentElement) if (scoped.has(p.tagName)) return false;
      return true;
    };
    return [...document.querySelectorAll('header,[role="banner"]')].filter(isBanner).length;
  });
  expect(banners, 'exactly one banner landmark').toBe(1);
}

/**
 * Load the page in a known theme with reduced motion actually in effect, and
 * assert the content every scan relies on is really on the page — including the
 * lab's DEFAULTS, which are never assumed.
 *
 * `test.use({ reducedMotion })` silently does nothing on Playwright 1.61.1, so
 * the emulation is applied imperatively BEFORE the navigation and then
 * *asserted* from inside the page. It has to be before `goto` for a reason
 * specific to this lab: `main.ts` evaluates
 * `matchMedia('(prefers-reduced-motion: reduce)').matches` ONCE at module scope
 * and caches it. A preference applied after load would change the CSS and not
 * the TypeScript, leaving the 45-frame counter animation and the smooth-scroll
 * preset behaviour live on a page whose stylesheet says motion is off.
 *
 * `goto('.')` with no query string is also load-bearing. Every knob on this page
 * round-trips through `window.location.search` (`parseState`), and `render()`
 * writes the current state back with `history.replaceState` — so a navigation
 * that carried a query string would be booting a DIFFERENT experiment while
 * this function asserted the defaults.
 *
 * The theme is seeded through `localStorage` rather than by clicking the
 * toggle, which also pins down a real failure mode: `index.html`'s anti-flash
 * script reads `localStorage.getItem('theme')` and the shared bar's toggle
 * writes `localStorage.setItem('theme', …)`. If those keys drift apart the
 * theme silently stops persisting, and this boot fails on `data-theme` rather
 * than quietly scanning dark twice.
 *
 * The defaults are asserted at length because THE DEFAULTS SELECT WHICH HALF OF
 * THIS LAB GETS SCANNED. `DEFAULTS` in `main.ts` ships the Heys S-box, three
 * rounds, the high nibble, 1024 pairs and the "Verified" approximation mode —
 * which together are the configuration that RECOVERS the key. The failure
 * verdicts, the rejected-approximation state and the custom-mask controls are
 * all somewhere else, and a gate that assumed the arrival state would never
 * find out if it moved.
 */
export async function boot(page: Page, theme: 'dark' | 'light'): Promise<void> {
  // A click on a control that never becomes actionable otherwise burns the whole
  // test timeout and reports nothing useful. 20s turns that silent hang into a
  // named failure naming the locator.
  page.setDefaultTimeout(20_000);
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.addInitScript((t) => localStorage.setItem('theme', t), theme);
  await page.goto('.');
  expect(
    await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
    'reduced-motion emulation must actually be in effect'
  ).toBe(true);
  await expect(page.locator('html')).toHaveAttribute('data-theme', theme);
  await assertSingleBanner(page);

  // `main.ts` resolves every element through a `$()` that THROWS on a miss and
  // then renders seven panels, so a navigation that resolves proves nothing.
  await expect(page.locator('main#app')).toBeVisible();
  await expect(page.locator('#app section')).toHaveCount(8);
  await expect(page.locator('.wayfinder a')).toHaveCount(4);

  // ── The shipped experiment ───────────────────────────────────────────────
  // Every one of these is a radio the segmented controls build at runtime; the
  // ids come from `renderSeg(container, name, …)` as `${name}-${value}`.
  for (const id of ['traffic-1024', 'rounds-3', 'sbox-heys', 'half-high', 'approx-auto']) {
    await expect(page.locator(`#${id}`)).toBeChecked();
  }
  await expect(page.locator('#custom-masks')).toBeHidden();
  await expect(page.locator('#mask-start')).toHaveValue('9');
  await expect(page.locator('#mask-end')).toHaveValue('192');
  await expect(page.locator('#plaintext-input')).toHaveValue('42');

  // ── Nothing has been counted ─────────────────────────────────────────────
  await expect(page.locator('#key-value')).toHaveText('4 hidden bits');
  await expect(page.locator('#key-reveal')).toHaveAttribute('aria-pressed', 'false');
  await expect(page.locator('#key-reveal')).toHaveText('Peek at the key');
  await expect(page.locator('#attack-verdict')).toHaveClass('verdict is-armed');
  await expect(page.locator('#attack-verdict')).toContainText('READY — NOTHING COUNTED YET');
  await expect(page.locator('#run-status')).toHaveClass('run-status is-idle');
  await expect(page.locator('#attack-run')).toBeEnabled();
  // Sixteen candidate rows are on screen from the first paint, all empty. The
  // ranking is not a thing the run creates; it is a thing the run fills in.
  await expect(page.locator('#attack-ranking tbody tr')).toHaveCount(16);
  await expect(page.locator('#attack-ranking .rank-bar.is-empty')).toHaveCount(16);

  // ── Panels that render themselves from the configuration on mount ────────
  // Four stages, joined by three `<li class="mech-arrow" aria-hidden>` glyphs —
  // so the list holds seven items and only four of them are stages.
  await expect(page.locator('#mechanism-chain li.mech-stage')).toHaveCount(4);
  await expect(page.locator('#mechanism-chain li.mech-arrow')).toHaveCount(3);
  await expect(page.locator('#lat-table .lat-cell')).toHaveCount(256);
  await expect(page.locator('#trace .trace-stage.is-target')).toHaveCount(1);
  await expect(page.locator('#piling-status')).toContainText('0 of');
  await expect(page.locator('#piling-step')).toBeEnabled();
  await expect(page.locator('#piling-step')).toHaveText('Apply the first round');

  // ── The measurement has not been run, and its cancel control ships absent ─
  await expect(page.locator('#measure-result')).toBeEmpty();
  await expect(page.locator('#measure-cancel')).toBeHidden();
  await expect(page.locator('#measure-run')).toHaveText('Measure the real success rate');

  // Five disclosures, all shut. `.tune` is the only route to the S-box, target
  // nibble, approximation mode and custom-mask controls, so "shut" is also the
  // reason four of this lab's controls are not reachable at first paint.
  await expect(page.locator('details')).toHaveCount(5);
  await expect(page.locator('details[open]')).toHaveCount(0);

  await settle(page);
  await expectNotBlank(page, `${theme} first paint`);
}

/**
 * Assert that `[hidden]` actually hides.
 *
 * `[hidden]` is a UA rule of specificity (0,0,0) in the author-facing sense —
 * any author `display` declaration beats it, including a single class — so
 * `hidden` can be set on an element and do nothing at all. Seven labs in this
 * fleet shipped that.
 *
 * This one already defends against it: `style.css` opens with an explicit
 * `[hidden] { display: none !important }`. The check stays because the defence
 * is one line in an 1800-line stylesheet and the two elements that depend on it
 * are both consequential — `#custom-masks` holds the mask inputs that must not
 * be reachable outside custom mode, and `#measure-cancel` is a Cancel button for
 * a measurement that is not running. Asserting the computed `display` is what
 * turns "there is a rule" into "the rule works".
 */
export async function expectHiddenActuallyHides(page: Page): Promise<void> {
  const leaks = await page.evaluate(() => {
    const out: string[] = [];
    for (const id of ['custom-masks', 'measure-cancel']) {
      const el = document.getElementById(id);
      if (!el) {
        out.push(`${id}: missing`);
        continue;
      }
      const had = el.hasAttribute('hidden');
      el.setAttribute('hidden', '');
      const display = getComputedStyle(el).display;
      if (!had) el.removeAttribute('hidden');
      if (display !== 'none') out.push(`#${id} computes display:${display} while [hidden]`);
    }
    return out;
  });
  expect(leaks, '[hidden] must actually hide — a class-level display beats it').toEqual([]);
}

/**
 * Assert the page does not require horizontal scrolling.
 *
 * WCAG 1.4.10 (Reflow, AA). axe has no rule for this at all, and this page is
 * the shape that breaks it: a 16x16 table of 256 buttons, a five-column counter
 * ranking, a three-column comparison table whose cells are full sentences, a
 * round-by-round cipher trace laid out in a row, and eight monospaced
 * `.equation` / `.formula` blocks. Every one of those is meant to scroll inside
 * its own box; the assertion here is that none of them scrolls the DOCUMENT.
 */
export async function expectNoHorizontalOverflow(page: Page, label: string): Promise<void> {
  const overflow = await page.evaluate(() => {
    const doc = document.documentElement;
    if (doc.scrollWidth <= doc.clientWidth) return null;

    // Only elements that actually push the DOCUMENT sideways are culprits. A
    // wide box inside an `overflow-x: auto` wrapper has a huge bounding rect but
    // is clipped by its scroller and contributes nothing to the document's
    // scroll width — naming it sends you off fixing the wrong element. That cost
    // a run elsewhere in this fleet, and this page has a decoy behind each of
    // its eleven scrollers, the widest being a 16x16 table of buttons.
    const clipped = (el: Element): boolean => {
      let n = el.parentElement;
      while (n && n !== doc) {
        const ox = getComputedStyle(n).overflowX;
        if (ox === 'auto' || ox === 'scroll' || ox === 'hidden' || ox === 'clip') return true;
        n = n.parentElement;
      }
      return false;
    };

    const over = Array.from(document.querySelectorAll('body *'))
      .map((el) => ({ el, r: el.getBoundingClientRect() }))
      .filter((x) => x.r.width > 0 && x.r.right > doc.clientWidth + 1)
      .sort((a, b) => b.r.right - a.r.right);
    const widest = over.filter((x) => !clipped(x.el))[0] ?? over[0];
    return {
      scrollWidth: doc.scrollWidth,
      clientWidth: doc.clientWidth,
      widest: widest
        ? `${clipped(widest.el) ? '[clipped] ' : ''}${widest.el.tagName.toLowerCase()}${widest.el.id ? '#' + widest.el.id : ''}` +
          `${widest.el.getAttribute('class') ? '.' + widest.el.getAttribute('class')!.trim().split(/\s+/).join('.') : ''}` +
          ` @${Math.round(widest.r.width)}px right=${Math.round(widest.r.right)}`
        : '(none identified)',
    };
  });
  expect(overflow, `page must not scroll horizontally in state: ${label}`).toBeNull();
}

/**
 * Every scrolling container must be operable from the keyboard (WCAG 2.1.1). If
 * it holds no focusable content it needs `tabindex="0"`, so it becomes a focus
 * target arrow keys can then scroll.
 *
 * This lab already handles its five known cases — `.ranking-wrap`,
 * `.lat-grid-wrap`, `#trace-wrap`, `#piling-decay` and `.compare-wrap` all
 * carry `role="region"`, `tabindex="0"` and an `aria-label` in the markup. The
 * assertion stays because those five are a convention rather than an
 * enforcement, and because SIX MORE `overflow-x: auto` boxes exist with none of
 * it: `.lat-evidence-wrap`, and every `.equation` and `.formula`. Those hold the
 * sixteen worked rows behind a LAT cell and the piling-up arithmetic, and
 * whether they overflow depends on the viewport and on which cell is selected —
 * a question only a drive can answer.
 */
export async function expectScrollersReachable(page: Page, label: string): Promise<void> {
  const unreachable = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,[tabindex]:not([tabindex="-1"])';
    return Array.from(document.querySelectorAll<HTMLElement>('body *'))
      .filter((el) => el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1)
      .filter((el) => {
        const cs = getComputedStyle(el);
        return (
          ['auto', 'scroll'].includes(cs.overflowX) || ['auto', 'scroll'].includes(cs.overflowY)
        );
      })
      .filter((el) => el.tabIndex < 0 && !el.querySelector(FOCUSABLE))
      .map(
        (el) =>
          `${el.tagName.toLowerCase()}${el.id ? '#' + el.id : ''}.${(el.getAttribute('class') ?? '').trim()}` +
          ` (${el.scrollWidth}x${el.scrollHeight} in ${el.clientWidth}x${el.clientHeight})`
      );
  });
  expect(
    Array.from(new Set(unreachable)),
    `scrolling regions with no keyboard route in state: ${label}`
  ).toEqual([]);
}

/**
 * Every tab stop must show WHERE the focus is (WCAG 2.4.7).
 *
 * This is here because it is the defect a reflow or 2.1.1 fix CREATES: making a
 * wide panel focusable so it can be scrolled from the keyboard adds a tab stop,
 * and a tab stop with no visible indicator is a new 2.4.7 failure. This lab has
 * five `tabindex="0"` regions added for exactly that reason (`.ranking-wrap`,
 * `.lat-grid-wrap`, `#trace-wrap`, `#piling-decay`, `.compare-wrap`) and —
 * unusually for this fleet — a focus rule written as `#app :focus-visible`,
 * which is element-agnostic and therefore already reaches them. This asserts
 * that outcome instead of trusting the selector, and it also covers the 256 LAT
 * cell buttons and the segmented controls, whose ring is drawn on the `<label>`
 * beside a visually-hidden radio (`.seg-input:focus-visible + .seg-label`) — a
 * shape where the focused element and the styled element are different nodes.
 *
 * It walks the REAL tab order with real Tab presses rather than calling
 * `focus()` in a loop, because `:focus-visible` is modality-dependent:
 * programmatic focus on a `<div>` does not match it, so a `focus()`-based check
 * would report a failure for every correctly-styled region and a pass for
 * nothing. `outline-style: auto` counts as an indicator — that is the UA focus
 * ring, which is a real one.
 */
export async function expectFocusVisibleThroughTabOrder(
  page: Page,
  label: string
): Promise<void> {
  // Identity is tracked by ELEMENT, in a page-side array, not by a describe()
  // string: this page has 256 `button.lat-cell`, sixteen `.seg-input` radios and
  // two `a.cl-btn` that all share a description, and a string-keyed set declares
  // the walk "wrapped" at the first repeat.
  await page.evaluate(() => {
    (window as unknown as { __tabStops?: Element[] }).__tabStops = [];
    (document.activeElement as HTMLElement | null)?.blur?.();
  });
  const bad = new Set<string>();
  let stops = 0;
  for (let i = 0; i < 200; i += 1) {
    await page.keyboard.press('Tab');
    const stop = await page.evaluate(() => {
      const seen = (window as unknown as { __tabStops: Element[] }).__tabStops;
      const el = document.activeElement as HTMLElement | null;
      // Focus has left the document's focusable set — Tab from the LAST tab
      // stop lands on <body>. That is not the end of the walk: the next Tab
      // re-enters at the top. Returning `null` (rather than stopping) is what
      // lets a walk that starts mid-document — which it does at the end of the
      // drive, because the last thing clicked was a <summary> near the bottom —
      // still reach every stop. Stopping here reported a 4-stop tab order.
      if (!el || el === document.body || el === document.documentElement) return 'edge';
      if (seen.includes(el)) return 'wrapped';
      seen.push(el);
      const cs = getComputedStyle(el);
      const w = parseFloat(cs.outlineWidth || '0');
      const drawn =
        (cs.outlineStyle !== 'none' && (cs.outlineStyle === 'auto' || w > 0)) ||
        (!!cs.boxShadow && cs.boxShadow !== 'none');
      const cls = (el.getAttribute('class') ?? '').trim().split(/\s+/).filter(Boolean).join('.');
      return {
        id: `${el.tagName.toLowerCase()}${el.id ? '#' + el.id : ''}${cls ? '.' + cls : ''}`,
        drawn,
        detail: `outline ${cs.outlineStyle} ${cs.outlineWidth}, box-shadow ${cs.boxShadow}`,
      } as const;
    });
    if (stop === 'edge') continue;
    if (stop === 'wrapped') break;
    stops += 1;
    if (!stop.drawn) bad.add(`${stop.id} — ${stop.detail}`);
  }
  await page.evaluate(() => {
    delete (window as unknown as { __tabStops?: Element[] }).__tabStops;
  });
  expect(stops, `tab order must have stops in state: ${label}`).toBeGreaterThan(10);
  expect(
    Array.from(bad),
    `tab stops with no visible focus indicator in state: ${label}`
  ).toEqual([]);
}

/**
 * When `A11Y_COLLECT` is set, `scan` records failures instead of throwing.
 *
 * A strict gate reports the first failing assertion in the first failing state
 * and stops, so a page with defects in several states needs one full run per
 * defect to enumerate them. The collection pass turns that into a single run. It
 * is a debugging aid only: `A11Y_COLLECT` is never set in CI or in the committed
 * workflow, and a run with it set prints every finding as it happens and then
 * fails at the end, so a green collection run cannot be mistaken for a green
 * gate.
 */
const COLLECTING = !!process.env.A11Y_COLLECT;
const collected: string[] = [];

function record(entry: string): void {
  collected.push(entry);
  // Printed as it happens, not only at the end: a hard assertion later in the
  // drive would otherwise abort the test before anything collected so far was
  // ever shown.
  console.log(`\n[A11Y_COLLECT #${collected.length}] ${entry}`);
}

export function softExpect(actual: unknown, message: string, expected: unknown): void {
  if (!COLLECTING) {
    expect(actual, message).toEqual(expected);
    return;
  }
  try {
    expect(actual, message).toEqual(expected);
  } catch {
    record(`${message}\n  ${JSON.stringify(actual, null, 2)}`);
  }
}

/** Same, for the assertions that live inside an async page probe. */
async function soft(fn: () => Promise<void>): Promise<void> {
  if (!COLLECTING) return fn();
  try {
    await fn();
  } catch (e) {
    record(String(e).slice(0, 900));
  }
}

/**
 * Fail the test if the collection pass recorded anything. Without this a
 * collection run would end green, and a green collection run is
 * indistinguishable from a green gate — which is the exact confusion the whole
 * exercise exists to remove.
 */
export function reportCollected(): void {
  if (!COLLECTING) return;
  expect(collected, `A11Y_COLLECT recorded ${collected.length} failure(s)`).toEqual([]);
}

/**
 * Scan the page as it currently stands.
 *
 * Seven assertions, because axe's `violations` array alone is not a complete
 * oracle. (The eighth, WCAG 2.4.7, is `expectFocusVisibleThroughTabOrder`,
 * which is not called from here because it MOVES focus — walking the whole tab
 * order inside every scan would change the state being scanned. It is driven
 * separately at the two states where this page's tab order differs: first
 * paint, and the fully populated page.)
 *
 *  - reduced-motion end state — see `expectNotBlank`.
 *  - `violations` — the usual WCAG A/AA rule failures, plus four landmark
 *    best-practice rules `withTags` does not run on its own.
 *  - `incomplete` — axe's "could not decide" bucket, which never reaches the
 *    violations array. The one rule id allowed to remain incomplete is
 *    `color-contrast`, and only because the next assertion computes those
 *    ratios arithmetically — which matters here because `.cockpit` paints a
 *    `linear-gradient` and axe declines to resolve one. Everything else in that
 *    bucket is a real result axe simply could not finish — including
 *    `aria-prohibited-attr`, which is where an `aria-label` on a role-less
 *    element hides, a defect that never reaches the violations array at all.
 *    This page puts an `aria-label` on five plain `<div>`s and makes each legal
 *    with `role="region"`; dropping one role is a one-character edit.
 *  - arithmetic contrast — composite-aware WCAG 1.4.3 over every text node.
 *  - non-text contrast — SC 1.4.11 control boundaries AND `::before`/`::after`
 *    generated content, neither of which axe has a rule for and neither of
 *    which the text walk can reach. See `e2e/nontext.ts`.
 *  - keyboard reachability of scrolling regions — WCAG 2.1.1.
 *  - reflow — WCAG 1.4.10, which axe has no rule for at all.
 */
export async function scan(page: Page, label: string): Promise<void> {
  await settle(page);
  await expectNotBlank(page, label);
  // TWO axe runs, deliberately, and this is not a style choice.
  //
  // `AxeBuilder.withTags()` and `AxeBuilder.withRules()` both write `runOnly`,
  // so the second call SILENTLY REPLACES the first — the axe-core/playwright
  // source says so in as many words ("Cannot be used with AxeBuilder#withTags").
  // Chained as `.withTags(TAGS).withRules([...])`, which is the form this gate
  // was copied from, axe ran those best-practice rules and NOT ONE WCAG RULE.
  // Measured on the source repo: the chained form executes 4 rules where
  // `withTags` alone executes 63. A green result meant "no duplicate landmarks"
  // and nothing whatever about WCAG A/AA, while reading like a full pass.
  //
  // Running the two sets separately and merging is the only way to have both.
  // The landmark rules are wanted because they are best-practice rather than
  // WCAG-tagged, so `withTags` alone does not reach them.
  const wcag = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const landmarks = await new AxeBuilder({ page }).withRules([ 'landmark-no-duplicate-banner', 'landmark-unique', 'landmark-one-main', 'landmark-complementary-is-top-level', ]).analyze();
  const results = {
    violations: [...wcag.violations, ...landmarks.violations],
    incomplete: [...wcag.incomplete, ...landmarks.incomplete],
  };

  const violations = results.violations.map((v) => ({
    state: label,
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
  }));
  softExpect(violations, `axe violations in state: ${label}`, []);

  const unexplainedIncomplete = results.incomplete
    .filter((v) => v.id !== 'color-contrast')
    .map((v) => ({
      state: label,
      id: v.id,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
    }));
  softExpect(unexplainedIncomplete, `axe incomplete results in state: ${label}`, []);

  const contrast = Array.from(new Set(formatContrastFailures(await auditContrast(page))));
  softExpect(contrast, `measured contrast failures in state: ${label}`, []);

  // A 1.4.11 oracle that silently measured nothing would be the same failure
  // this sweep exists to remove, so the population is asserted before the
  // verdict: `#app` must really contain visible controls to judge.
  expect(
    await page.locator('#app button:visible, #app input:visible').count(),
    `no controls found to measure in state: ${label}`
  ).toBeGreaterThan(0);
  softExpect(
    Array.from(new Set(formatNonTextFailures(await auditNonText(page)))),
    `non-text contrast failures (SC 1.4.11 / generated content) in state: ${label}`,
    []
  );

  await soft(() => expectScrollersReachable(page, label));
  await soft(() => expectNoHorizontalOverflow(page, label));
}


// ── The drive ───────────────────────────────────────────────────────────────

/**
 * Pick one option of a segmented control.
 *
 * The `<input type="radio">` behind each option is `position: absolute; width:
 * 1px; opacity: 0; pointer-events: none`, so it cannot be clicked and
 * `check()` cannot reach it — the visible control is the `<label>`. Clicking
 * the label is also what a reader does, and it is the only route that exercises
 * `.seg-input:checked + .seg-label`, the rule that paints the selection.
 */
async function pick(page: Page, group: string, value: string): Promise<void> {
  await page.click(`label[for="${group}-${value}"]`);
  await expect(page.locator(`#${group}-${value}`)).toBeChecked();
}

/** The three verdict classes `renderVerdict` can produce for a finished run. */
const FINISHED_VERDICT = /verdict is-(broken|partial|held)/;

/**
 * Wait for a run to finish and return the verdict class that landed.
 *
 * Under the reduced motion this gate asserts, `runAttackAnimated` advances all
 * sixteen counters in one call, so "finished" is reached synchronously — but
 * the assertion is on the DOM signal the code itself defines (`run-status
 * is-done`), never on a timeout.
 */
async function finished(page: Page): Promise<string> {
  await expect(page.locator('#run-status')).toHaveClass('run-status is-done');
  await expect(page.locator('#attack-verdict')).toHaveClass(FINISHED_VERDICT);
  await expect(page.locator('#attack-ranking tbody tr')).toHaveCount(16);
  return (await page.locator('#attack-verdict').getAttribute('class')) ?? '';
}

/**
 * Open every VISIBLE shut disclosure by clicking its summary.
 *
 * `:visible` is load-bearing here: `.tune` contains no nested `<details>`, but
 * the three `.deep` panels and `.jargon` are all in the static markup while
 * their CONTENT is rendered by `main.ts` — so a run that opens them before the
 * page has rendered would be opening empty boxes.
 */
async function openAllDisclosures(page: Page, expectSome = true): Promise<void> {
  const shut = page.locator('details:not([open]) > summary:visible');
  let opened = 0;
  for (let i = await shut.count(); i > 0 && opened < 20; i = await shut.count()) {
    await shut.first().click();
    opened += 1;
  }
  await expect(page.locator('details:not([open]) > summary:visible')).toHaveCount(0);
  if (expectSome) {
    expect(opened, 'no shut disclosure was found where one was expected').toBeGreaterThan(0);
  }
}

/**
 * Drive the lab through the states that render content, scanning each.
 *
 * Six things shape this drive:
 *
 *  - THE ARRIVAL STATE IS SCANNED FIRST, AND IT IS A REAL STATE. Sixteen empty
 *    counter rows, an "READY — NOTHING COUNTED YET" verdict, a rendered cipher
 *    trace, a full 16x16 LAT and a piling-up panel at zero rounds revealed. The
 *    gate this replaces reached it only through a document with all five
 *    disclosures forced open and every `[hidden]` element stripped.
 *
 *  - EVERY VERDICT THE PAGE CAN REACH. `renderVerdict` has three outcomes —
 *    `is-broken` (recovered), `is-partial` (a structural tie at the top) and
 *    `is-held` (not recovered) — plus `is-armed`, `is-stale` and the rejected
 *    state, each with its own ink and its own icon. The drive reaches every one
 *    of them and records which landed, because they are the states where a
 *    contrast slip would hide.
 *
 *  - EVERY ERROR STATE, WHICH IS THREE DISTINCT MESSAGES. A last-round mask that
 *    straddles both nibbles, a last-round mask of zero, and a plaintext mask of
 *    zero each produce a different rejection, and each is prose the reader is
 *    meant to read in a surface (`verdict is-partial` + `run-status is-blocked`)
 *    nothing else on the page uses.
 *
 *  - THE EXTREMES, NOT THE DEFAULTS. Traffic at 16 and at the whole codebook,
 *    rounds at 2 and 4, both S-boxes, both target nibbles, both plaintext-slider
 *    ends. Several of those are the only route to a state that exists: 4 rounds
 *    on the codebook is the only configuration where the page says the attack
 *    has hit its ceiling rather than run out of luck.
 *
 *  - THE MEASUREMENT, INCLUDING ITS CANCEL PATH. 300 complete attacks in a
 *    module Worker, with a live progress region and a Cancel button that ships
 *    `hidden` — three renderings (progress, result table, cancelled) that no
 *    previous gate had scanned, and the only place `#measure-cancel` is visible.
 *
 *  - NO FIXED TIMEOUTS. Every step has a DOM completion signal — a status class,
 *    a row count, a button's text, a region becoming visible — and the drive
 *    waits on those.
 */
export async function driveAllStates(page: Page, theme: string): Promise<void> {
  const scanAt = (s: string): Promise<void> => scan(page, `${theme} / ${s}`);

  await expectHiddenActuallyHides(page);
  await scanAt('first paint: sixteen empty counters, five disclosures shut');

  await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur?.());
  await page.keyboard.press('Tab');
  await expect(page.locator('a.cl-skip-link')).toBeFocused();
  await scanAt('shared-header skip link focused');

  // Ordered after the skip-link step deliberately: the walk leaves a sequential
  // focus navigation starting point behind that `blur()` does not reset, so
  // running it first makes "one Tab from the top lands on the skip link"
  // untestable.
  await soft(() => expectFocusVisibleThroughTabOrder(page, `${theme} / first paint`));

  // ── The key card, and that hiding it again restores the shipped text ──────
  await page.click('#key-reveal');
  await expect(page.locator('#key-reveal')).toHaveAttribute('aria-pressed', 'true');
  await expect(page.locator('#key-reveal')).toHaveText('Hide the key');
  await expect(page.locator('#key-value')).toHaveText(/^0x[0-9A-F]{4} → /);
  await scanAt('the key revealed');
  await page.click('#key-reveal');
  await expect(page.locator('#key-value')).toHaveText('4 hidden bits');
  await scanAt('the key hidden again, back to the shipped reading');

  // ── The attack at the shipped configuration ──────────────────────────────
  await page.click('#attack-run');
  const shipped = await finished(page);
  await expect(page.locator('#run-status')).toContainText('Counted 1,024 known pairs.');
  await expect(page.locator('#key-value')).toHaveText(/^nibble recovered: 0x[0-9A-F]$/);
  await scanAt(`attack run at the shipped configuration (${shipped})`);

  // ── Stale: a result standing under settings that have since moved ────────
  await pick(page, 'rounds', '2');
  await expect(page.locator('#attack-verdict')).toHaveClass('verdict is-stale');
  await expect(page.locator('#run-status')).toHaveClass('run-status is-stale');
  await scanAt('configuration changed under a finished result — the stale state');

  await page.click('#attack-run');
  await finished(page);
  await scanAt('two rounds: the approximation barely decays');

  // ── The four scenario presets, each of which runs itself ─────────────────
  await page.click('#preset-starve');
  await finished(page);
  await expect(page.locator('#run-status')).toContainText('Counted 16 known pairs.');
  await scanAt('starved: sixteen pairs of evidence');

  // Four rounds on the whole codebook is the only configuration where the page
  // can say the attack has hit its CEILING rather than run out of luck, and on
  // this cipher it is the one that does not recover.
  await page.click('#preset-round');
  const fourRound = await finished(page);
  await expect(page.locator('#run-status')).toContainText('Counted 256 known pairs.');
  // The verdict is NOT asserted to a single class here, because the page
  // generates a fresh 16-bit key on every load and the outcome genuinely
  // depends on it — measured over 24 pinned keys, 23 do not recover at four
  // rounds and one does. Pinning it would be the honest way to assert a class,
  // and that is exactly what the pinned segment at the end of this drive does;
  // asserting one here would be asserting a coin flip.
  await scanAt(`four rounds on the whole codebook (${fourRound})`);

  // A deliberately dead approximation: valid masks with no trail through the
  // S-boxes at all, which is also the only state where the piling-up panel has
  // nothing to compound and its Step button ships disabled.
  await page.click('#preset-bad');
  await finished(page);
  // The preset switches the Approximation control to "My own masks", so the
  // mask inputs stop being `hidden` — but they are inside the `.tune`
  // disclosure, which is still shut, so they are not on screen either. That is
  // the state the preset actually produces, and asserting the attribute rather
  // than visibility is what says so.
  await expect(page.locator('#custom-masks')).not.toHaveAttribute('hidden', /.*/);
  await expect(page.locator('#custom-masks')).toBeHidden();
  await expect(page.locator('#piling-step')).toBeDisabled();
  await expect(page.locator('#piling-rounds .is-pending')).toBeVisible();
  await scanAt('an unbiased approximation: no trail, nothing to compound');

  await page.click('#preset-reset');
  await finished(page);
  // Reset must return the page to the shipped experiment, not merely to a
  // working one.
  for (const id of ['traffic-1024', 'rounds-3', 'sbox-heys', 'half-high', 'approx-auto']) {
    await expect(page.locator(`#${id}`)).toBeChecked();
  }
  await expect(page.locator('#custom-masks')).toBeHidden();
  await scanAt('Reset: back to the shipped experiment');

  // ── The tuning drawer, and the three ways an approximation is rejected ───
  await page.locator('details.tune > summary').click();
  await expect(page.locator('details.tune')).toHaveAttribute('open', '');
  await scanAt('the tuning drawer open');

  await pick(page, 'approx', 'custom');
  await expect(page.locator('#custom-masks')).toBeVisible();
  await scanAt('custom masks revealed');

  // 193 = 0b1100_0001, which reads one bit of the LOW nibble while the target is
  // the high one. One nibble guess can only undo one nibble of the substitution.
  await page.locator('#mask-end').fill('193');
  await expect(page.locator('#attack-run')).toBeDisabled();
  await expect(page.locator('#attack-verdict')).toHaveClass('verdict is-partial');
  await expect(page.locator('#attack-verdict')).toContainText('APPROXIMATION REJECTED');
  await expect(page.locator('#run-status')).toHaveClass('run-status is-blocked');
  await expect(page.locator('#mask-note')).toContainText('outside the high nibble');
  await scanAt('rejected: a last-round mask straddling both nibbles');

  await page.locator('#mask-end').fill('0');
  await expect(page.locator('#mask-note')).toContainText('selects no bits');
  await scanAt('rejected: a last-round mask that selects nothing');

  await page.locator('#mask-end').fill('192');
  await page.locator('#mask-start').fill('0');
  await expect(page.locator('#mask-note')).toContainText('the constant 0');
  await scanAt('rejected: a plaintext mask that selects nothing');

  await page.locator('#mask-start').fill('9');
  await expect(page.locator('#attack-run')).toBeEnabled();
  await page.click('#attack-run');
  await finished(page);
  await scanAt('the hand-written masks, run');

  // ── The other two approximation modes ────────────────────────────────────
  await pick(page, 'approx', 'ranked');
  await page.click('#attack-run');
  await finished(page);
  await scanAt('the strongest trail the lemma finds, used unscreened');
  await pick(page, 'approx', 'auto');
  await page.click('#attack-run');
  await finished(page);
  await scanAt('back to the screened approximation');

  // ── The other S-box, and the other target nibble ─────────────────────────
  await pick(page, 'sbox', 'present');
  await expect(page.locator('#sbox-note')).not.toBeEmpty();
  await page.click('#attack-run');
  await finished(page);
  await scanAt('the PRESENT S-box, whose design caps its linear bias');

  await pick(page, 'half', 'low');
  await page.click('#attack-run');
  await finished(page);
  await scanAt('targeting the low nibble of the final subkey');

  await pick(page, 'half', 'high');
  await pick(page, 'sbox', 'heys');

  // ── Both ends of the traffic control ─────────────────────────────────────
  await pick(page, 'traffic', 'codebook');
  await expect(page.locator('#traffic-note')).toContainText('no sampling luck');
  await page.click('#attack-run');
  await finished(page);
  await scanAt('the entire codebook: no sampling error left in the result');

  await pick(page, 'traffic', '4096');
  await page.click('#attack-run');
  await finished(page);
  await scanAt('the largest sampled traffic setting');
  await pick(page, 'traffic', '1024');
  await page.click('#attack-run');
  await finished(page);

  // ── The cipher walkthrough, at both ends of its slider ───────────────────
  await page.locator('#plaintext-input').fill('0');
  await expect(page.locator('#plaintext-note')).toHaveText('Plaintext 0x00');
  await expect(page.locator('#trace .trace-stage.is-target')).toHaveCount(1);
  await scanAt('the cipher trace on plaintext 0x00');
  await page.locator('#plaintext-input').fill('255');
  await expect(page.locator('#plaintext-note')).toHaveText('Plaintext 0xFF');
  await scanAt('the cipher trace on plaintext 0xFF');

  // ── The LAT, in each of the three shapes a cell can have ────────────────
  for (const [a, b, why] of [
    [11, 4, 'a leaking cell'],
    [1, 1, 'a nearly balanced cell'],
    [0, 3, 'a trivial cell in the zero row'],
  ] as const) {
    await page.click(`.lat-cell[data-a="${a}"][data-b="${b}"]`);
    await expect(page.locator(`.lat-cell[data-a="${a}"][data-b="${b}"]`)).toHaveAttribute(
      'aria-pressed',
      'true'
    );
    await expect(page.locator('#lat-detail')).not.toBeEmpty();
    await scanAt(`LAT cell ${a},${b} selected — ${why}`);
  }

  // ── The piling-up lemma, stepped to the end and reset ────────────────────
  const step = page.locator('#piling-step');
  for (let i = 0; i < 6 && (await step.isEnabled()); i += 1) await step.click();
  await expect(step).toBeDisabled();
  await expect(page.locator('#piling-status')).toContainText(/^All \d+ rounds applied/);
  await scanAt('every round of the trail applied, the bias compounded');

  await page.click('#piling-reset');
  await expect(page.locator('#piling-status')).toContainText(/^0 of \d+ rounds applied/);
  await expect(step).toBeEnabled();
  await expect(step).toHaveText('Apply the first round');
  await scanAt('the piling-up trail reset to nothing revealed');

  await page.click('#piling-step');
  await expect(page.locator('#piling-status')).toContainText(/^1 of \d+ rounds applied/);
  await expect(step).toHaveText('Add the next round');
  await scanAt('one round of the trail applied');

  // ── The measured success curve, off the main thread ─────────────────────
  // The cancel path first, and with NO scan between the two clicks. 300
  // complete attacks finish in about a second in this Worker, and a scan is
  // slower than that — putting one in the middle let the run complete and then
  // scanned the finished curve under the label "the measurement running",
  // which is a mislabelled state and the thing this whole exercise exists to
  // stop. The transient progress rendering is therefore a NAMED coverage gap,
  // like the counting phase: it cannot be held still without lying to the page.
  await page.click('#measure-run');
  await expect(page.locator('#measure-cancel')).toBeVisible();
  await expect(page.locator('#measure-run')).toBeDisabled();
  await page.click('#measure-cancel');
  await expect(page.locator('#measure-cancel')).toBeHidden();
  await expect(page.locator('#measure-progress')).toContainText('Measurement cancelled');
  await expect(page.locator('#measure-result')).toBeEmpty();
  await scanAt('the measurement cancelled, nothing partial reported');

  await page.click('#measure-run');
  // The result table is the completion signal the code itself defines. 300
  // complete attacks is genuinely slow, so the wait is long — but it is a wait
  // on the DOM, not a sleep.
  await expect(page.locator('#measure-result .curve')).toBeVisible({ timeout: 180_000 });
  await expect(page.locator('#measure-result .curve tbody tr')).toHaveCount(5);
  await expect(page.locator('#measure-run')).toHaveText('Measure again');
  await expect(page.locator('#measure-progress')).toContainText('complete attacks run');
  await scanAt('the measured success curve beside the predicted one');

  // ── The share link ───────────────────────────────────────────────────────
  await page.click('#copy-link');
  await expect(page.locator('#copy-link')).toHaveText('Link copied — reproduces this exact run');
  await scanAt('the experiment link copied');

  // ── Everything open ──────────────────────────────────────────────────────
  await openAllDisclosures(page);
  await expect(page.locator('details[open]')).toHaveCount(5);
  await scanAt('the finished page with all five disclosures open');
  await soft(() => expectFocusVisibleThroughTabOrder(page, `${theme} / fully populated`));

  // ── All three finished verdicts, pinned ─────────────────────────────────
  // Everything above ran on the random key the page mints on load, so which
  // verdict lands is not a property of the drive. These three URLs make it one:
  // the key travels in `?k=` by design (`state/url.ts` says so in as many
  // words), and with the whole codebook or a fixed `seed` there is no sampling
  // left either. The values were found by measurement, not by guess — 24 keys
  // were run through both configurations to locate one of each.
  for (const [query, expected, what] of [
    ['?k=1&rounds=3&n=1024&sbox=heys&half=high&approx=auto&seed=7', 'is-broken', 'KEY RECOVERED'],
    ['?k=1&rounds=4&n=codebook&sbox=heys&half=high&approx=auto', 'is-held', 'NOT RECOVERED'],
    ['?k=16&rounds=3&n=1024&sbox=heys&half=high&approx=auto&seed=7', 'is-partial', 'PARTIAL'],
  ] as const) {
    await page.goto(query);
    await expect(page.locator('#attack-run')).toBeEnabled();
    await page.click('#attack-run');
    await expect(page.locator('#attack-verdict')).toHaveClass(`verdict ${expected}`);
    await expect(page.locator('#attack-verdict')).toContainText(what);
    await settle(page);
    await scanAt(`pinned experiment: the ${expected} verdict (${what})`);
  }
}
