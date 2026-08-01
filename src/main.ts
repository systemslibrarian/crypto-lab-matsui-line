import './style.css';

import {
  collectKnownPairs,
  fullCodebook,
  measureSuccessRate,
  requiredSamples,
  runAttack,
  screenApproximation,
  selectApproximation,
  type AttackResult,
  type SelectedApproximation,
} from './crypto/attack.js';
import { bestTrail, latFor, rankApproximations, trailBetween, type Trail } from './crypto/trail.js';
import { getSbox, type SboxName } from './crypto/sbox.js';
import { randomKey, traceEncryption, type NibbleHalf, type SpnKey } from './crypto/spn.js';
import { mulberry32, randomSeed } from './crypto/rng.js';

import { renderTrace } from './ui/cipher.js';
import { renderLatDetail, renderLatTable, type TrailCell } from './ui/lat.js';
import { renderDecay, renderPilingResult, renderTrailSteps, renderTrailTruth, type DecayPoint } from './ui/piling.js';
import { renderRanking, renderScreening, renderVerdict } from './ui/attackView.js';
import { renderCalculator, renderCurve } from './ui/samples.js';
import { asFraction, bin8, hex, magnitude, maskTerms, maskTermsPlain, percent } from './ui/format.js';

type ApproxMode = 'auto' | 'ranked' | 'custom';

interface State {
  sboxName: SboxName;
  cipherRounds: number;
  half: NibbleHalf;
  sampleExponent: number;
  key: SpnKey;
  revealKey: boolean;
  plaintext: number;
  latSelection: { a: number; b: number } | null;
  approxMode: ApproxMode;
  customStart: number;
  customEnd: number;
  pilingRevealed: number;
  attack: { result: AttackResult; wholeCodebook: boolean; samples: number } | null;
}

const state: State = {
  sboxName: 'heys',
  cipherRounds: 3,
  half: 'high',
  sampleExponent: 10,
  key: randomKey(),
  revealKey: false,
  plaintext: 42,
  latSelection: null,
  approxMode: 'auto',
  customStart: 0b0000_1001,
  customEnd: 0b1100_0000,
  pilingRevealed: 0,
  attack: null,
};

const $ = <T extends HTMLElement>(id: string): T => {
  const el = document.getElementById(id);
  if (!el) throw new Error(`missing element #${id}`);
  return el as T;
};

/* ── Derived state ─────────────────────────────────────────────────── */

const selectionCache = new Map<string, SelectedApproximation | null>();

function currentSbox() {
  return getSbox(state.sboxName);
}

function autoSelection(): SelectedApproximation | null {
  const cacheKey = `${state.sboxName}:${state.cipherRounds}:${state.half}`;
  if (!selectionCache.has(cacheKey)) {
    selectionCache.set(cacheKey, selectApproximation(currentSbox(), state.cipherRounds, state.half));
  }
  return selectionCache.get(cacheKey) ?? null;
}

interface Approximation {
  trail: Trail | null;
  startMask: number;
  endMask: number;
  selected: SelectedApproximation | null;
  /** Why the attack cannot run, if it cannot. */
  error: string | null;
}

function currentApproximation(): Approximation {
  const sbox = currentSbox();
  const approxRounds = state.cipherRounds - 1;

  if (state.approxMode === 'custom') {
    const start = state.customStart & 0xff;
    const end = state.customEnd & 0xff;
    const stray = state.half === 'low' ? end & 0xf0 : end & 0x0f;
    let error: string | null = null;
    if (end === 0) {
      error = 'The last-round mask selects no bits, so the relation says nothing. Pick at least one bit.';
    } else if (stray !== 0) {
      error = `The last-round mask reads bits outside the ${state.half} nibble. One nibble guess can only undo one nibble of the substitution — narrow the mask or switch target nibble.`;
    } else if (start === 0) {
      error = 'The plaintext mask selects no bits: the left-hand side is the constant 0, which carries no key information.';
    }
    return {
      trail: error ? null : trailBetween(sbox, approxRounds, start, end),
      startMask: start,
      endMask: end,
      selected: null,
      error,
    };
  }

  if (state.approxMode === 'ranked') {
    const top = rankApproximations(sbox, approxRounds, { endHalf: state.half, limit: 1 })[0];
    if (!top) return { trail: null, startMask: 0, endMask: 0, selected: null, error: 'No trail exists.' };
    const trail = trailBetween(sbox, approxRounds, top.startMask, top.endMask);
    const screen = screenApproximation(sbox, state.cipherRounds, state.half, top.startMask, top.endMask);
    return {
      trail,
      startMask: top.startMask,
      endMask: top.endMask,
      selected: trail
        ? { trail, screen, screened: 1, rank: 1, usable: screen.outrightBreaks === screen.trials }
        : null,
      error: null,
    };
  }

  const selected = autoSelection();
  if (!selected) return { trail: null, startMask: 0, endMask: 0, selected: null, error: 'No trail exists.' };
  return {
    trail: selected.trail,
    startMask: selected.trail.startMask,
    endMask: selected.trail.endMask,
    selected,
    error: null,
  };
}

function sampleCount(): number {
  return 2 ** state.sampleExponent;
}

/* ── Rendering ─────────────────────────────────────────────────────── */

function renderCipherPanel(): void {
  const sbox = currentSbox();
  $('sbox-note').textContent = sbox.note;
  $('rounds-note').textContent =
    state.cipherRounds === 2
      ? 'One S-box layer between plaintext and the attacked round: the approximation barely decays, and the attack is close to trivial.'
      : state.cipherRounds === 3
        ? 'A reduced-round variant. Linear cryptanalysis reaches this far on an 8-bit block; see exhibit 6 for why.'
        : 'The full cipher, identical to the one Biham Lens attacks. Run the attack below and watch what one extra round costs you.';

  $('plaintext-note').innerHTML = `Plaintext ${hex(state.plaintext)} = <code>${bin8(state.plaintext)}</code>`;

  const keyValue = $<HTMLOutputElement>('key-value');
  keyValue.textContent = state.revealKey
    ? `${hex(state.key.masterKey, 4)} → subkeys ${state.key.subkeys.map((k) => hex(k)).join(' ')}`
    : 'hidden — you are the attacker';

  renderTrace($('trace'), traceEncryption(state.plaintext, state.key, sbox, state.cipherRounds));
}

function trailCells(trail: Trail | null): TrailCell[] {
  if (!trail) return [];
  const cells: TrailCell[] = [];
  for (const step of trail.steps) {
    for (const nibble of step.nibbles) {
      if (nibble.active) cells.push({ a: nibble.inMask, b: nibble.outMask, round: step.round });
    }
  }
  return cells;
}

function renderLatPanel(): void {
  const sbox = currentSbox();
  const lat = latFor(sbox);
  const approximation = currentApproximation();
  const cells = trailCells(approximation.trail);

  if (state.latSelection === null) {
    state.latSelection = cells.length > 0 ? { a: cells[0].a, b: cells[0].b } : { a: 0b1011, b: 0b0100 };
  }

  renderLatTable($<HTMLTableElement>('lat-table'), lat, state.latSelection, cells);
  renderLatDetail($('lat-detail'), sbox, lat, state.latSelection.a, state.latSelection.b);

  const zeros = lat.counts.slice(1).reduce((n, row) => n + row.slice(1).filter((v) => v === 0).length, 0);
  $('lat-summary').innerHTML = `
    225 non-trivial approximations. ${zeros} of them are perfectly balanced and useless; the rest leak, the worst by
    ${magnitude(lat.maxAbsBiasCount / 16, 16)}. Ringed cells are the ones the current trail rides on.
    An S-box cannot be made of zeros — Parseval's identity forces every row to carry the same total squared bias, so
    designers can only spread the leak thinly, never remove it.
  `;
}

function renderPilingPanel(): void {
  const approximation = currentApproximation();
  const list = $('piling-rounds');
  const result = $('piling-result');
  const truth = $('piling-truth');

  if (!approximation.trail) {
    list.innerHTML = `<li class="piling-round is-pending"><div class="piling-round-body">No trail joins these two masks — every chain of masks between them passes through a zero in the table. The piling-up lemma has nothing to compound, so the predicted bias is exactly 0.</div></li>`;
    result.innerHTML = `<span class="stat-label">Predicted bias</span><span class="big-number">0</span><p class="control-note">An approximation with no trail is a coin flip by construction. Run the attack with it anyway — watching a hopeless approximation fail is worth as much as watching a good one succeed.</p>`;
    truth.innerHTML = '<p>Nothing to compare: this pair of masks has no trail through the S-boxes.</p>';
    $('piling-status').textContent = '';
    renderDecay($('piling-decay'), decayPoints());
    return;
  }

  const trail = approximation.trail;
  const revealed = Math.min(state.pilingRevealed, trail.steps.length);
  renderTrailSteps(list, trail, revealed);
  renderPilingResult(result, trail, revealed);
  renderTrailTruth(truth, currentSbox(), state.key, state.cipherRounds, trail);
  renderDecay($('piling-decay'), decayPoints());

  const stepBtn = $<HTMLButtonElement>('piling-step');
  stepBtn.disabled = revealed >= trail.steps.length;
  stepBtn.textContent = revealed === 0 ? 'Apply the first round' : 'Add the next round';
  $('piling-status').textContent =
    revealed >= trail.steps.length
      ? `All ${trail.steps.length} rounds applied — bias ${asFraction(trail.bias, 4096)}.`
      : `${revealed} of ${trail.steps.length} rounds applied.`;
}

/** Best bias reachable over 1, 2 and 3 S-box layers, with its data cost. */
function decayPoints(): DecayPoint[] {
  const sbox = currentSbox();
  const points: DecayPoint[] = [];
  for (let layers = 1; layers <= 3; layers++) {
    const trail = bestTrail(sbox, layers, { endHalf: state.half });
    if (!trail) continue;
    points.push({
      layers,
      bias: trail.bias,
      samplesNeeded: requiredSamples(trail.bias, 0.977),
    });
  }
  return points;
}

function renderAttackPanel(): void {
  const approximation = currentApproximation();
  const samples = sampleCount();

  $('samples-note').textContent = `${samples.toLocaleString()} pairs (2^${state.sampleExponent})`;
  $('approx-note').textContent =
    state.approxMode === 'auto'
      ? 'Ranked by the piling-up lemma, then screened against the real cipher. The demo default.'
      : state.approxMode === 'ranked'
        ? 'The strongest trail the lemma can find, used without checking whether it can actually separate the keys.'
        : 'Your masks. Most combinations do nothing at all — that is the lesson.';

  $('custom-masks').hidden = state.approxMode !== 'custom';

  const maskNote = $('mask-note');
  if (approximation.error) {
    maskNote.textContent = approximation.error;
  } else if (state.approxMode === 'custom') {
    maskNote.innerHTML = `${maskTerms(approximation.startMask, 'P', 8)} = ${maskTerms(approximation.endMask, 'U', 8)} · predicted bias ${asFraction(approximation.trail?.bias ?? 0, 4096)}`;
  }

  $('approx-readout').innerHTML = approximation.error
    ? '—'
    : `${maskTerms(approximation.startMask, 'P', 8)} = ${maskTerms(approximation.endMask, 'U', 8)} &nbsp;·&nbsp; ε = ${asFraction(approximation.trail?.bias ?? 0, 4096)}`;

  $<HTMLButtonElement>('attack-run').disabled = approximation.error !== null;
  $<HTMLButtonElement>('attack-codebook').disabled = approximation.error !== null;

  const verdict = $('attack-verdict');
  const ranking = $<HTMLTableElement>('attack-ranking');

  if (approximation.error) {
    verdict.className = 'verdict is-partial';
    verdict.innerHTML = `<div class="verdict-head"><span class="verdict-icon" aria-hidden="true">!</span><span>APPROXIMATION REJECTED</span></div><p>${approximation.error}</p>`;
    ranking.innerHTML = ranking.querySelector('caption')?.outerHTML ?? '';
  } else if (state.attack) {
    renderVerdict(verdict, state.attack.result, {
      half: state.half,
      cipherRounds: state.cipherRounds,
      samples: state.attack.samples,
      trail: approximation.trail,
      wholeCodebook: state.attack.wholeCodebook,
      usable: approximation.selected ? approximation.selected.usable : null,
      ceiling: approximation.selected ? approximation.selected.screen.ceiling : null,
    });
    renderRanking(ranking, state.attack.result);
  } else {
    verdict.className = 'verdict';
    verdict.innerHTML = `<div class="verdict-head"><span class="verdict-icon" aria-hidden="true">?</span><span>NOT RUN YET</span></div><p>Collect some traffic and see which of the sixteen candidates leans.</p>`;
    ranking.innerHTML = ranking.querySelector('caption')?.outerHTML ?? '';
  }

  const screening = $('attack-screen');
  if (approximation.selected) {
    renderScreening(screening, approximation.selected, state.half);
  } else {
    screening.innerHTML =
      '<p>Screening applies to the approximations the search proposes. These masks are yours, so there is nothing to report — run the attack and read the ranking directly.</p>';
  }
}

function renderSamplesPanel(): void {
  const approximation = currentApproximation();
  renderCalculator($('calc'), approximation.trail?.bias ?? 0, sampleCount());
}

function render(): void {
  renderCipherPanel();
  renderLatPanel();
  renderPilingPanel();
  renderAttackPanel();
  renderSamplesPanel();
}

/* ── Actions ───────────────────────────────────────────────────────── */

function runTheAttack(wholeCodebook: boolean): void {
  const approximation = currentApproximation();
  if (approximation.error) return;
  const sbox = currentSbox();
  const pairs = wholeCodebook
    ? fullCodebook(state.key, sbox, state.cipherRounds)
    : collectKnownPairs(state.key, sbox, state.cipherRounds, sampleCount(), mulberry32(randomSeed()));

  state.attack = {
    result: runAttack({
      sbox,
      key: state.key,
      cipherRounds: state.cipherRounds,
      half: state.half,
      startMask: approximation.startMask,
      endMask: approximation.endMask,
      pairs,
    }),
    wholeCodebook,
    samples: pairs.length,
  };
  renderAttackPanel();
}

function invalidateApproximation(): void {
  state.pilingRevealed = 0;
  state.latSelection = null;
  state.attack = null;
}

/* ── Wiring ────────────────────────────────────────────────────────── */

$<HTMLSelectElement>('sbox-select').addEventListener('change', (event) => {
  state.sboxName = (event.target as HTMLSelectElement).value as SboxName;
  invalidateApproximation();
  render();
});

$<HTMLSelectElement>('rounds-select').addEventListener('change', (event) => {
  state.cipherRounds = Number((event.target as HTMLSelectElement).value);
  invalidateApproximation();
  render();
});

$<HTMLSelectElement>('half-select').addEventListener('change', (event) => {
  state.half = (event.target as HTMLSelectElement).value as NibbleHalf;
  invalidateApproximation();
  render();
});

$<HTMLInputElement>('samples-input').addEventListener('input', (event) => {
  state.sampleExponent = Number((event.target as HTMLInputElement).value);
  renderAttackPanel();
  renderSamplesPanel();
});

$<HTMLInputElement>('plaintext-input').addEventListener('input', (event) => {
  state.plaintext = Number((event.target as HTMLInputElement).value);
  renderCipherPanel();
});

$<HTMLSelectElement>('approx-select').addEventListener('change', (event) => {
  state.approxMode = (event.target as HTMLSelectElement).value as ApproxMode;
  invalidateApproximation();
  render();
});

for (const id of ['mask-start', 'mask-end']) {
  $<HTMLInputElement>(id).addEventListener('input', (event) => {
    const value = Number((event.target as HTMLInputElement).value);
    const clamped = Number.isFinite(value) ? Math.max(0, Math.min(255, Math.trunc(value))) : 0;
    if (id === 'mask-start') state.customStart = clamped;
    else state.customEnd = clamped;
    invalidateApproximation();
    render();
  });
}

$('key-reveal').addEventListener('click', () => {
  state.revealKey = !state.revealKey;
  $('key-reveal').setAttribute('aria-pressed', String(state.revealKey));
  $('key-reveal').textContent = state.revealKey ? 'Hide' : 'Reveal';
  renderCipherPanel();
});

$('key-new').addEventListener('click', () => {
  state.key = randomKey();
  state.attack = null;
  render();
});

$('lat-table').addEventListener('click', (event) => {
  const button = (event.target as HTMLElement).closest<HTMLButtonElement>('.lat-cell');
  if (!button) return;
  state.latSelection = { a: Number(button.dataset.a), b: Number(button.dataset.b) };
  renderLatPanel();
});

$('piling-step').addEventListener('click', () => {
  state.pilingRevealed += 1;
  renderPilingPanel();
});

$('piling-reset').addEventListener('click', () => {
  state.pilingRevealed = 0;
  renderPilingPanel();
});

$('attack-run').addEventListener('click', () => runTheAttack(false));
$('attack-codebook').addEventListener('click', () => runTheAttack(true));

$('measure-run').addEventListener('click', () => {
  const approximation = currentApproximation();
  const target = $('measure-result');
  if (approximation.error) {
    target.innerHTML = '<p>Fix the approximation above first.</p>';
    return;
  }
  const button = $<HTMLButtonElement>('measure-run');
  button.disabled = true;
  button.textContent = 'Measuring…';
  // Yield once so the button state paints before the measurement blocks.
  window.setTimeout(() => {
    const points = measureSuccessRate({
      sbox: currentSbox(),
      cipherRounds: state.cipherRounds,
      half: state.half,
      startMask: approximation.startMask,
      endMask: approximation.endMask,
      sampleCounts: [16, 64, 256, 1024, 4096],
      keyCount: 60,
      bias: approximation.trail?.bias ?? 0,
      seed: randomSeed(),
    });
    renderCurve(target, points);
    button.disabled = false;
    button.textContent = 'Measure again';
  }, 16);
});

/* ── Boot ──────────────────────────────────────────────────────────── */

render();
// Open on the whole codebook: the cleanest possible statement of the attack,
// with no sampling luck in it. The slider is there to take data away again and
// watch it stop working.
runTheAttack(true);

// A short, honest note in the console for anyone who opens it.
const boot = currentApproximation();
console.info(
  [
    'Matsui Line — linear cryptanalysis of a toy SPN.',
    `Approximation: ${maskTermsPlain(boot.startMask, 'P', 8)} = ${maskTermsPlain(boot.endMask, 'U', 8)}`,
    `Predicted bias ${asFraction(boot.trail?.bias ?? 0, 4096)}; screening ceiling ${
      boot.selected ? percent(boot.selected.screen.ceiling, 0) : 'n/a'
    }.`,
    'Not production cryptography — an 8-bit block exists to be broken in front of you.',
  ].join('\n'),
);
