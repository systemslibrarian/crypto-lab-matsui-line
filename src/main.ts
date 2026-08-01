import './style.css';

import {
  collectKnownPairs,
  fullCodebook,
  measureSuccessRate,
  requiredSamples,
  screenApproximation,
  selectApproximation,
  startAttack,
  type AttackCounter,
  type AttackResult,
  type SelectedApproximation,
  type SuccessPoint,
} from './crypto/attack.js';
import {
  bestTrail,
  deadApproximation,
  latFor,
  rankApproximations,
  trailBetween,
  type Trail,
} from './crypto/trail.js';
import { getSbox, type SboxName } from './crypto/sbox.js';
import { generateKey, traceEncryption, type NibbleHalf, type SpnKey } from './crypto/spn.js';
import { mulberry32, randomSeed } from './crypto/rng.js';
import {
  parseState,
  shareUrl,
  toSearch,
  TRAFFIC_CHOICES,
  type ApproxMode,
  type ExperimentState,
  type Traffic,
} from './state/url.js';

import { renderTrace } from './ui/cipher.js';
import { renderLatDetail, renderLatTable, type TrailCell } from './ui/lat.js';
import { renderDecay, renderPilingResult, renderTrailSteps, renderTrailTruth, type DecayPoint } from './ui/piling.js';
import { renderScreening, renderVerdict } from './ui/attackView.js';
import {
  renderCounters,
  renderCountersIdle,
  renderMeasureProgress,
  renderMechanism,
  renderStatus,
  type CockpitPhase,
  type MechanismStage,
} from './ui/cockpit.js';
import { renderCalculator, renderCurve } from './ui/samples.js';
import { asFraction, esc, hex, magnitude, maskTerms, maskTermsPlain, percent } from './ui/format.js';
import type { MeasureMessage, MeasureRequest } from './workers/measure.worker.js';

const $ = <T extends HTMLElement>(id: string): T => {
  const el = document.getElementById(id);
  if (!el) throw new Error(`missing element #${id}`);
  return el as T;
};

/* ── State ─────────────────────────────────────────────────────────── */

function randomMasterKey(): number {
  const buf = new Uint8Array(2);
  crypto.getRandomValues(buf);
  return ((buf[0] << 8) | buf[1]) & 0xffff;
}

const DEFAULTS: ExperimentState = {
  sboxName: 'heys',
  cipherRounds: 3,
  half: 'high',
  traffic: 1024,
  approxMode: 'auto',
  customStart: 0b0000_1001,
  customEnd: 0b1100_0000,
  masterKey: randomMasterKey(),
  seed: null,
};

const experiment: ExperimentState = parseState(window.location.search, DEFAULTS);

interface ViewState {
  key: SpnKey;
  revealKey: boolean;
  plaintext: number;
  latSelection: { a: number; b: number } | null;
  pilingRevealed: number;
  phase: CockpitPhase;
  /** The completed attack currently on screen, if any. */
  attack: { result: AttackResult; samples: number; wholeCodebook: boolean } | null;
  /** Seed actually used for the most recent run, for the share link. */
  lastRunSeed: number | null;
  animation: number | null;
  measureWorker: Worker | null;
}

const view: ViewState = {
  key: generateKey(experiment.masterKey),
  revealKey: false,
  plaintext: 42,
  latSelection: null,
  pilingRevealed: 0,
  phase: 'idle',
  attack: null,
  lastRunSeed: null,
  animation: null,
  measureWorker: null,
};

const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

/* ── Derived ───────────────────────────────────────────────────────── */

const selectionCache = new Map<string, SelectedApproximation | null>();

const currentSbox = () => getSbox(experiment.sboxName);

function autoSelection(): SelectedApproximation | null {
  const cacheKey = `${experiment.sboxName}:${experiment.cipherRounds}:${experiment.half}`;
  if (!selectionCache.has(cacheKey)) {
    selectionCache.set(cacheKey, selectApproximation(currentSbox(), experiment.cipherRounds, experiment.half));
  }
  return selectionCache.get(cacheKey) ?? null;
}

interface Approximation {
  trail: Trail | null;
  startMask: number;
  endMask: number;
  selected: SelectedApproximation | null;
  error: string | null;
}

function currentApproximation(): Approximation {
  const sbox = currentSbox();
  const approxRounds = experiment.cipherRounds - 1;

  if (experiment.approxMode === 'custom') {
    const start = experiment.customStart & 0xff;
    const end = experiment.customEnd & 0xff;
    const stray = experiment.half === 'low' ? end & 0xf0 : end & 0x0f;
    let error: string | null = null;
    if (end === 0) {
      error = 'The last-round mask selects no bits, so the relation says nothing. Pick at least one bit.';
    } else if (stray !== 0) {
      error = `The last-round mask reads bits outside the ${experiment.half} nibble. One nibble guess can only undo one nibble of the substitution — narrow the mask or switch target nibble.`;
    } else if (start === 0) {
      error =
        'The plaintext mask selects no bits: the left-hand side is the constant 0, which carries no key information.';
    }
    return {
      trail: error ? null : trailBetween(sbox, approxRounds, start, end),
      startMask: start,
      endMask: end,
      selected: null,
      error,
    };
  }

  if (experiment.approxMode === 'ranked') {
    const top = rankApproximations(sbox, approxRounds, { endHalf: experiment.half, limit: 1 })[0];
    if (!top) return { trail: null, startMask: 0, endMask: 0, selected: null, error: 'No trail exists.' };
    const trail = trailBetween(sbox, approxRounds, top.startMask, top.endMask);
    const screen = screenApproximation(sbox, experiment.cipherRounds, experiment.half, top.startMask, top.endMask);
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

const trafficCount = (): number => (experiment.traffic === 'codebook' ? 256 : experiment.traffic);

/* ── Segmented controls ────────────────────────────────────────────── */

interface SegOption<T> {
  readonly value: T;
  readonly label: string;
  readonly hint?: string;
}

function renderSeg<T extends string | number>(
  container: HTMLElement,
  name: string,
  options: readonly SegOption<T>[],
  active: T,
  onPick: (value: T) => void,
): void {
  container.innerHTML = options
    .map((option) => {
      const id = `${name}-${String(option.value)}`;
      const checked = option.value === active ? 'checked' : '';
      return `
        <input type="radio" class="seg-input" name="${name}" id="${id}" value="${esc(String(option.value))}" ${checked} />
        <label class="seg-label" for="${id}">${esc(option.label)}${
          option.hint ? `<span class="seg-hint">${esc(option.hint)}</span>` : ''
        }</label>`;
    })
    .join('');
  container.querySelectorAll<HTMLInputElement>('.seg-input').forEach((input) => {
    input.addEventListener('change', () => {
      if (!input.checked) return;
      const picked = options.find((o) => String(o.value) === input.value);
      if (picked) onPick(picked.value);
    });
  });
}

/* ── Rendering ─────────────────────────────────────────────────────── */

function renderControls(): void {
  renderSeg<string>(
    $('seg-traffic'),
    'traffic',
    TRAFFIC_CHOICES.map((t) => ({
      value: String(t),
      label: t === 'codebook' ? 'All 256' : t.toLocaleString(),
      hint: t === 'codebook' ? 'whole codebook' : undefined,
    })),
    String(experiment.traffic),
    (value) => {
      experiment.traffic = value === 'codebook' ? 'codebook' : (Number(value) as Traffic);
      invalidateRun();
    },
  );
  $('traffic-note').textContent =
    experiment.traffic === 'codebook'
      ? 'Every possible plaintext exactly once — no sampling luck left in the result.'
      : `${trafficCount().toLocaleString()} pairs drawn at random from ordinary traffic, with repeats.`;

  renderSeg<number>(
    $('seg-rounds'),
    'rounds',
    [
      { value: 2, label: '2' },
      { value: 3, label: '3' },
      { value: 4, label: '4', hint: 'full' },
    ],
    experiment.cipherRounds,
    (value) => {
      experiment.cipherRounds = value;
      invalidateApproximation();
    },
  );
  $('rounds-note').textContent =
    experiment.cipherRounds === 2
      ? 'One S-box layer to cross: the approximation barely decays and the attack is close to trivial.'
      : experiment.cipherRounds === 3
        ? 'A reduced-round variant — as far as linear cryptanalysis reaches on an 8-bit block.'
        : 'The full cipher, identical to the one Biham Lens attacks with differentials.';

  renderSeg<SboxName>(
    $('seg-sbox'),
    'sbox',
    [
      { value: 'heys', label: 'Heys' },
      { value: 'present', label: 'PRESENT' },
    ],
    experiment.sboxName,
    (value) => {
      experiment.sboxName = value;
      invalidateApproximation();
    },
  );
  $('sbox-note').textContent = currentSbox().note;

  renderSeg<NibbleHalf>(
    $('seg-half'),
    'half',
    [
      { value: 'high', label: 'High — bits 7…4' },
      { value: 'low', label: 'Low — bits 3…0' },
    ],
    experiment.half,
    (value) => {
      experiment.half = value;
      invalidateApproximation();
    },
  );

  renderSeg<ApproxMode>(
    $('seg-approx'),
    'approx',
    [
      { value: 'auto', label: 'Verified' },
      { value: 'ranked', label: 'Strongest, unverified' },
      { value: 'custom', label: 'My own masks' },
    ],
    experiment.approxMode,
    (value) => {
      experiment.approxMode = value;
      invalidateApproximation();
    },
  );
  $('approx-note').textContent =
    experiment.approxMode === 'auto'
      ? 'Ranked by the piling-up lemma, then screened against the real cipher. The demo default.'
      : experiment.approxMode === 'ranked'
        ? 'The strongest trail the lemma can find, used without checking it can separate the keys.'
        : 'Your masks. Most combinations do nothing at all — that is the lesson.';

  $('custom-masks').hidden = experiment.approxMode !== 'custom';
  ($('mask-start') as HTMLInputElement).value = String(experiment.customStart);
  ($('mask-end') as HTMLInputElement).value = String(experiment.customEnd);
}

function renderKeyCard(): void {
  const output = $<HTMLOutputElement>('key-value');
  const known = view.attack && view.phase === 'done' ? view.attack.result.trueNibble : null;
  if (view.revealKey) {
    output.textContent = `${hex(view.key.masterKey, 4)} → ${view.key.subkeys.map((k) => hex(k)).join(' ')}`;
  } else if (known !== null) {
    output.textContent = `nibble recovered: ${hex(known, 1)}`;
  } else {
    output.textContent = '4 hidden bits';
  }
  $('key-reveal').textContent = view.revealKey ? 'Hide the key' : 'Peek at the key';
  $('key-reveal').setAttribute('aria-pressed', String(view.revealKey));
}

function renderCipherPanel(): void {
  $('plaintext-note').innerHTML = `Plaintext ${hex(view.plaintext)}`;
  renderTrace($('trace'), traceEncryption(view.plaintext, view.key, currentSbox(), experiment.cipherRounds));
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
  const cells = trailCells(currentApproximation().trail);

  if (view.latSelection === null) {
    view.latSelection = cells.length > 0 ? { a: cells[0].a, b: cells[0].b } : { a: 0b1011, b: 0b0100 };
  }

  renderLatTable($<HTMLTableElement>('lat-table'), lat, view.latSelection, cells);
  renderLatDetail($('lat-detail'), sbox, lat, view.latSelection.a, view.latSelection.b);

  const zeros = lat.counts.slice(1).reduce((n, row) => n + row.slice(1).filter((v) => v === 0).length, 0);
  $('lat-summary').innerHTML = `
    225 non-trivial approximations. ${zeros} of them are perfectly balanced and useless; the rest leak, the worst by
    ${magnitude(lat.maxAbsBiasCount / 16, 16)}. An S-box cannot be made of zeros — Parseval's identity forces every row
    to carry the same total squared bias, so designers can only spread the leak thinly, never remove it.
  `;
}

function decayPoints(): DecayPoint[] {
  const sbox = currentSbox();
  const points: DecayPoint[] = [];
  for (let layers = 1; layers <= 3; layers++) {
    const trail = bestTrail(sbox, layers, { endHalf: experiment.half });
    if (!trail) continue;
    points.push({ layers, bias: trail.bias, samplesNeeded: requiredSamples(trail.bias, 0.977) });
  }
  return points;
}

function renderPilingPanel(): void {
  const approximation = currentApproximation();
  const list = $('piling-rounds');
  const result = $('piling-result');
  const truth = $('piling-truth');
  renderDecay($('piling-decay'), decayPoints());

  if (!approximation.trail) {
    list.innerHTML = `<li class="piling-round is-pending"><div class="piling-round-body">No trail joins these two masks — every chain of masks between them passes through a zero in the table. The piling-up lemma has nothing to compound, so the predicted bias is exactly 0.</div></li>`;
    result.innerHTML = `<span class="stat-label">Predicted bias</span><span class="big-number">0</span><p class="seg-note">An approximation with no trail is a coin flip by construction. Run the attack with it anyway — watching a hopeless approximation fail is worth as much as watching a good one succeed.</p>`;
    truth.innerHTML = '<p>Nothing to compare: this pair of masks has no trail through the S-boxes.</p>';
    $('piling-status').textContent = '';
    $<HTMLButtonElement>('piling-step').disabled = true;
    return;
  }

  const trail = approximation.trail;
  const revealed = Math.min(view.pilingRevealed, trail.steps.length);
  renderTrailSteps(list, trail, revealed);
  renderPilingResult(result, trail, revealed);
  renderTrailTruth(truth, currentSbox(), view.key, experiment.cipherRounds, trail);

  const stepBtn = $<HTMLButtonElement>('piling-step');
  stepBtn.disabled = revealed >= trail.steps.length;
  stepBtn.textContent = revealed === 0 ? 'Apply the first round' : 'Add the next round';
  $('piling-status').textContent =
    revealed >= trail.steps.length
      ? `All ${trail.steps.length} rounds applied — bias ${magnitude(trail.bias, 4096)}.`
      : `${revealed} of ${trail.steps.length} rounds applied.`;
}

function renderCockpit(): void {
  const approximation = currentApproximation();

  $('approx-readout').innerHTML = approximation.error
    ? '<span class="dim">no usable relation</span>'
    : `Relation under test: ${maskTerms(approximation.startMask, 'P', 8)} = ${maskTerms(
        approximation.endMask,
        'U',
        8,
      )} <span class="dim">· predicted bias ${asFraction(approximation.trail?.bias ?? 0, 4096)}</span>`;

  const maskNote = $('mask-note');
  if (approximation.error) maskNote.textContent = approximation.error;
  else if (experiment.approxMode === 'custom')
    maskNote.innerHTML = `${maskTerms(approximation.startMask, 'P', 8)} = ${maskTerms(approximation.endMask, 'U', 8)} · predicted bias ${asFraction(approximation.trail?.bias ?? 0, 4096)}`;

  const runButton = $<HTMLButtonElement>('attack-run');
  runButton.disabled = approximation.error !== null || view.phase === 'counting';

  const verdict = $('attack-verdict');
  const ranking = $<HTMLTableElement>('attack-ranking');

  if (approximation.error) {
    renderStatus($('run-status'), { phase: 'blocked', processed: 0, total: 0, message: approximation.error });
    verdict.className = 'verdict is-partial';
    verdict.innerHTML = `<div class="verdict-head"><span class="verdict-icon" aria-hidden="true">!</span><span>APPROXIMATION REJECTED</span></div><p>${esc(approximation.error)}</p>`;
    renderCountersIdle(ranking);
  } else if (view.phase === 'counting' && view.attack) {
    renderStatus($('run-status'), {
      phase: 'counting',
      processed: view.attack.result.samples,
      total: view.attack.samples,
    });
    verdict.className = 'verdict is-counting';
    verdict.innerHTML = `<div class="verdict-head"><span class="verdict-icon" aria-hidden="true">◐</span><span>COUNTING…</span></div><p>Sixteen counters, one per candidate. Watch for one of them to stop looking like a coin flip.</p>`;
    renderCounters(ranking, view.attack.result, { reveal: false, order: 'fixed' });
  } else if (view.phase === 'done' && view.attack) {
    renderStatus($('run-status'), { phase: 'done', processed: view.attack.samples, total: view.attack.samples });
    renderVerdict(verdict, view.attack.result, {
      half: experiment.half,
      cipherRounds: experiment.cipherRounds,
      samples: view.attack.samples,
      trail: approximation.trail,
      wholeCodebook: view.attack.wholeCodebook,
      usable: approximation.selected ? approximation.selected.usable : null,
      ceiling: approximation.selected ? approximation.selected.screen.ceiling : null,
    });
    renderCounters(ranking, view.attack.result, { reveal: true, order: 'ranked' });
  } else if (view.phase === 'stale') {
    renderStatus($('run-status'), { phase: 'stale', processed: 0, total: 0 });
    verdict.className = 'verdict is-stale';
    verdict.innerHTML = `<div class="verdict-head"><span class="verdict-icon" aria-hidden="true">↻</span><span>CONFIGURATION CHANGED</span></div><p>The settings moved after that result was produced, so it no longer describes what is on screen. Run the attack again.</p>`;
    renderCountersIdle(ranking);
  } else {
    renderStatus($('run-status'), { phase: 'idle', processed: 0, total: 0 });
    verdict.className = 'verdict is-armed';
    verdict.innerHTML = `<div class="verdict-head"><span class="verdict-icon" aria-hidden="true">○</span><span>READY — NOTHING COUNTED YET</span></div><p>Sixteen candidates, no evidence. Collect ${trafficCount().toLocaleString()} known ${
      trafficCount() === 1 ? 'pair' : 'pairs'
    } and see which candidate stops looking like a coin flip.</p>`;
    renderCountersIdle(ranking);
  }

  const screening = $('attack-screen');
  if (approximation.selected) renderScreening(screening, approximation.selected, experiment.half);
  else
    screening.innerHTML =
      '<p>Screening applies to the approximations the search proposes. These masks are yours, so there is nothing to report — run the attack and read the ranking directly.</p>';

  renderKeyCard();
}

function renderMechanismPanel(): void {
  const approximation = currentApproximation();
  const lat = latFor(currentSbox());
  const trail = approximation.trail;
  const firstActive = trail?.steps[0]?.nibbles.find((n) => n.active) ?? null;
  const result = view.phase === 'done' ? view.attack?.result ?? null : null;

  const stages: MechanismStage[] = [
    {
      id: 'sbox',
      target: 'lat',
      label: 'One S-box is not balanced',
      value: firstActive
        ? `${(lat.counts[firstActive.inMask][firstActive.outMask] + 8).toString()} / 16 agreements`
        : '—',
      note: firstActive
        ? `mask ${firstActive.inMask.toString(2).padStart(4, '0')} → ${firstActive.outMask
            .toString(2)
            .padStart(4, '0')}, a bias of ${magnitude(lat.counts[firstActive.inMask][firstActive.outMask] / 16, 16)} instead of nothing`
        : 'no active S-box in this relation',
      pending: !firstActive,
    },
    {
      id: 'trail',
      target: 'piling',
      label: 'The leak survives the rounds, shrinking',
      value: trail ? `ε = ${asFraction(trail.bias, 4096)}` : 'ε = 0',
      note: trail
        ? `${trail.steps.map((s) => magnitude(s.bias, 16)).join(' × ')} across ${trail.steps.length} ${
            trail.steps.length === 1 ? 'round' : 'rounds'
          }, piled up`
        : 'no trail joins these masks — nothing to compound',
      pending: !trail,
    },
    {
      id: 'count',
      target: 'attack',
      label: 'Sixteen counters over real traffic',
      value: result ? `${result.samples.toLocaleString()} pairs counted` : 'not run yet',
      note: result
        ? `each candidate peels the last round its own way; only one of them is undoing what the cipher did`
        : 'press Run in exhibit 1 to collect the evidence',
      pending: !result,
    },
    {
      id: 'separate',
      target: 'attack',
      label: 'One candidate separates',
      value: result
        ? result.recovered
          ? `${percent(Math.abs(result.scores[result.trueNibble].bias) + 0.5, 1)} vs ~50%`
          : 'no separation'
        : '—',
      note: result
        ? result.recovered
          ? `the winner beat the loudest wrong guess by ${magnitude(
              Math.abs(result.scores[result.trueNibble].deviation) -
                Math.max(...result.scores.filter((s) => s.guess !== result.trueNibble).map((s) => s.deviation)),
              4096,
            )} — and it is the key`
          : 'the real key stayed in the pack; the leak was too small to hear over the wrong guesses'
        : 'the payoff: the correct guess is the one that makes the leak reappear',
      pending: !result,
    },
  ];

  renderMechanism($('mechanism-chain'), stages);
}

function renderSamplesPanel(): void {
  renderCalculator($('calc'), currentApproximation().trail?.bias ?? 0, trafficCount());
}

function render(): void {
  renderControls();
  renderCockpit();
  renderMechanismPanel();
  renderCipherPanel();
  renderLatPanel();
  renderPilingPanel();
  renderSamplesPanel();
  syncUrl();
}

function syncUrl(): void {
  window.history.replaceState(null, '', `${window.location.pathname}${toSearch(experiment)}`);
}

/* ── Running the attack ────────────────────────────────────────────── */

function stopAnimation(): void {
  if (view.animation !== null) {
    cancelAnimationFrame(view.animation);
    view.animation = null;
  }
}

/** Any change that would make the displayed result describe different settings. */
function invalidateRun(): void {
  stopAnimation();
  if (view.attack !== null) {
    view.attack = null;
    view.phase = 'stale';
  } else {
    view.phase = 'idle';
  }
  render();
}

function invalidateApproximation(): void {
  view.pilingRevealed = 0;
  view.latSelection = null;
  invalidateRun();
}

function runAttackAnimated(): void {
  const approximation = currentApproximation();
  if (approximation.error) return;
  stopAnimation();

  const sbox = currentSbox();
  const seed = experiment.seed ?? randomSeed();
  view.lastRunSeed = seed;
  const pairs =
    experiment.traffic === 'codebook'
      ? fullCodebook(view.key, sbox, experiment.cipherRounds)
      : collectKnownPairs(view.key, sbox, experiment.cipherRounds, trafficCount(), mulberry32(seed));

  const counter: AttackCounter = startAttack({
    sbox,
    key: view.key,
    cipherRounds: experiment.cipherRounds,
    half: experiment.half,
    startMask: approximation.startMask,
    endMask: approximation.endMask,
    pairs,
  });

  const finish = (): void => {
    view.phase = 'done';
    view.attack = {
      result: counter.snapshot(),
      samples: counter.total,
      wholeCodebook: experiment.traffic === 'codebook',
    };
    renderCockpit();
    renderMechanismPanel();
    renderSamplesPanel();
  };

  if (prefersReducedMotion) {
    counter.advance(counter.total);
    finish();
    return;
  }

  // Roughly 900ms of counting regardless of N, so 16 pairs and 4096 pairs both
  // read as "this is being counted" rather than "this was already decided".
  const frames = 45;
  const batch = Math.max(1, Math.ceil(counter.total / frames));
  view.phase = 'counting';
  view.attack = { result: counter.snapshot(), samples: counter.total, wholeCodebook: experiment.traffic === 'codebook' };
  renderCockpit();

  const tick = (): void => {
    counter.advance(batch);
    if (counter.done) {
      view.animation = null;
      finish();
      return;
    }
    view.attack = {
      result: counter.snapshot(),
      samples: counter.total,
      wholeCodebook: experiment.traffic === 'codebook',
    };
    renderCockpit();
    view.animation = requestAnimationFrame(tick);
  };
  view.animation = requestAnimationFrame(tick);
}

/* ── Scenario presets ──────────────────────────────────────────────── */

function applyPreset(changes: Partial<ExperimentState>): void {
  Object.assign(experiment, changes);
  invalidateApproximation();
  $('attack').scrollIntoView({ behavior: prefersReducedMotion ? 'auto' : 'smooth', block: 'start' });
  runAttackAnimated();
}

/* ── Wiring ────────────────────────────────────────────────────────── */

for (const id of ['mask-start', 'mask-end']) {
  $<HTMLInputElement>(id).addEventListener('input', (event) => {
    const value = Number((event.target as HTMLInputElement).value);
    const clamped = Number.isFinite(value) ? Math.max(0, Math.min(255, Math.trunc(value))) : 0;
    if (id === 'mask-start') experiment.customStart = clamped;
    else experiment.customEnd = clamped;
    invalidateApproximation();
  });
}

$('key-reveal').addEventListener('click', () => {
  view.revealKey = !view.revealKey;
  renderKeyCard();
});

$('key-new').addEventListener('click', () => {
  experiment.masterKey = randomMasterKey();
  view.key = generateKey(experiment.masterKey);
  view.revealKey = false;
  invalidateRun();
});

$('attack-run').addEventListener('click', () => runAttackAnimated());

$('preset-starve').addEventListener('click', () => applyPreset({ traffic: 16 }));
$('preset-round').addEventListener('click', () => applyPreset({ cipherRounds: 4, traffic: 'codebook' }));
$('preset-bad').addEventListener('click', () => {
  const dead = deadApproximation(currentSbox(), experiment.cipherRounds - 1, experiment.half);
  applyPreset({
    approxMode: 'custom',
    customStart: dead?.startMask ?? 1,
    customEnd: dead?.endMask ?? (experiment.half === 'high' ? 0x80 : 0x01),
  });
});
$('preset-reset').addEventListener('click', () =>
  applyPreset({ sboxName: 'heys', cipherRounds: 3, half: 'high', traffic: 1024, approxMode: 'auto' }),
);

$('copy-link').addEventListener('click', async () => {
  const button = $<HTMLButtonElement>('copy-link');
  const url = shareUrl({ ...experiment, seed: view.lastRunSeed ?? experiment.seed ?? randomSeed() }, window.location.href);
  try {
    await navigator.clipboard.writeText(url);
    button.textContent = 'Link copied — reproduces this exact run';
  } catch {
    button.textContent = 'Copy failed — the link is in the address bar';
  }
  window.setTimeout(() => {
    button.textContent = 'Copy experiment link';
  }, 2600);
});

$('lat-table').addEventListener('click', (event) => {
  const button = (event.target as HTMLElement).closest<HTMLButtonElement>('.lat-cell');
  if (!button) return;
  view.latSelection = { a: Number(button.dataset.a), b: Number(button.dataset.b) };
  renderLatPanel();
});

$('plaintext-input').addEventListener('input', (event) => {
  view.plaintext = Number((event.target as HTMLInputElement).value);
  renderCipherPanel();
});

$('piling-step').addEventListener('click', () => {
  view.pilingRevealed += 1;
  renderPilingPanel();
  renderMechanismPanel();
});

$('piling-reset').addEventListener('click', () => {
  view.pilingRevealed = 0;
  renderPilingPanel();
});

/* ── Measurement, off the main thread ──────────────────────────────── */

const SAMPLE_COUNTS = [16, 64, 256, 1024, 4096];
const MEASURE_KEYS = 60;

function stopMeasurement(): void {
  view.measureWorker?.terminate();
  view.measureWorker = null;
  $<HTMLButtonElement>('measure-run').disabled = false;
  $<HTMLButtonElement>('measure-run').textContent = 'Measure again';
  $('measure-cancel').hidden = true;
}

$('measure-run').addEventListener('click', () => {
  const approximation = currentApproximation();
  if (approximation.error) {
    $('measure-progress').innerHTML = '<p>Fix the approximation in exhibit 1 first.</p>';
    return;
  }
  const button = $<HTMLButtonElement>('measure-run');
  button.disabled = true;
  button.textContent = 'Measuring…';
  $('measure-cancel').hidden = false;

  const request: MeasureRequest = {
    sboxName: experiment.sboxName,
    cipherRounds: experiment.cipherRounds,
    half: experiment.half,
    startMask: approximation.startMask,
    endMask: approximation.endMask,
    sampleCounts: SAMPLE_COUNTS,
    keyCount: MEASURE_KEYS,
    bias: approximation.trail?.bias ?? 0,
    seed: experiment.seed ?? randomSeed(),
  };

  const showResult = (points: SuccessPoint[], seed: number): void => {
    renderCurve($('measure-result'), points);
    $('measure-progress').innerHTML = `<p class="seg-note">${(
      SAMPLE_COUNTS.length * MEASURE_KEYS
    ).toLocaleString()} complete attacks run, seed <code>${seed}</code>.</p>`;
    stopMeasurement();
  };

  try {
    const worker = new Worker(new URL('./workers/measure.worker.ts', import.meta.url), { type: 'module' });
    view.measureWorker = worker;
    renderMeasureProgress($('measure-progress'), 0, SAMPLE_COUNTS.length * MEASURE_KEYS);
    worker.onmessage = (event: MessageEvent<MeasureMessage>) => {
      const message = event.data;
      if (message.kind === 'progress') renderMeasureProgress($('measure-progress'), message.completed, message.total);
      else if (message.kind === 'done') showResult(message.points, message.seed);
      else {
        $('measure-progress').innerHTML = `<p>Measurement failed: ${esc(message.message)}</p>`;
        stopMeasurement();
      }
    };
    worker.onerror = () => {
      // No worker available (older browser, blocked module worker): do it here.
      stopMeasurement();
      showResult(measureSuccessRate({ ...request, sbox: currentSbox() }), request.seed);
    };
    worker.postMessage(request);
  } catch {
    showResult(measureSuccessRate({ ...request, sbox: currentSbox() }), request.seed);
  }
});

$('measure-cancel').addEventListener('click', () => {
  stopMeasurement();
  $('measure-progress').innerHTML = '<p class="seg-note">Measurement cancelled — nothing partial is reported.</p>';
});

/* ── Wayfinder ─────────────────────────────────────────────────────── */

const wayfinderTargets = ['attack', 'mechanism', 'samples', 'honesty'];
if ('IntersectionObserver' in window) {
  const links = new Map(
    wayfinderTargets.map((id) => [id, document.querySelector<HTMLAnchorElement>(`.wayfinder a[data-way="${id}"]`)]),
  );
  const observer = new IntersectionObserver(
    (entries) => {
      for (const entry of entries) {
        if (!entry.isIntersecting) continue;
        for (const [, link] of links) link?.removeAttribute('aria-current');
        links.get(entry.target.id)?.setAttribute('aria-current', 'true');
      }
    },
    { rootMargin: '-20% 0px -70% 0px' },
  );
  for (const id of wayfinderTargets) {
    const section = document.getElementById(id);
    if (section) observer.observe(section);
  }
}

/* ── Boot ──────────────────────────────────────────────────────────── */

render();

console.info(
  [
    'Matsui Line — linear cryptanalysis of a toy SPN.',
    `Relation: ${maskTermsPlain(currentApproximation().startMask, 'P', 8)} = ${maskTermsPlain(
      currentApproximation().endMask,
      'U',
      8,
    )}`,
    'Nothing is precomputed for show: every counter you see move was counted.',
    'Not production cryptography — an 8-bit block exists to be broken in front of you.',
  ].join('\n'),
);
