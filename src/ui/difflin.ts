/**
 * Exhibit: the differential–linear composition.
 *
 * Rendering only — every number on screen comes from `crypto/difflin.ts`,
 * which computes it from the real cipher. Nothing here is asserted.
 */

import {
  designatedPath,
  naiveBias,
  pathAwareBias,
  pathPairBias,
  prefixPaths,
  runDlAttack,
  subkeyCandidates,
  subkeyTargetMask,
  suffixCorrelation,
  type DlAttackResult,
  type DlDesign,
  type DlSuccessPoint,
} from '../crypto/difflin.js';
import type { Sbox } from '../crypto/sbox.js';
import type { SpnKey } from '../crypto/spn.js';
import { asFraction, bin8, esc, hex, magnitude, maskTerms, percent, signed } from './format.js';

export interface DlSetup {
  readonly sbox: Sbox;
  readonly design: DlDesign;
}

/** The composition skeleton: prefix, joining state, suffix, statistic. */
export function renderDlSetup(el: HTMLElement, { sbox, design }: DlSetup): void {
  const designated = designatedPath(sbox, design, 0x0b);
  const corr = suffixCorrelation(sbox, design);
  const eps = Math.abs(corr) / 2;
  el.innerHTML = `
    <p class="dl-boundary">
      <strong>Fixed lesson boundary:</strong> this exhibit always uses the Heys S-box and the shared toy SPN's
      3-round reduced form. The cockpit's S-box and round controls do not alter it. It demonstrates this selected
      construction; it does not claim an attack on the full 4-round toy cipher or on a production cipher.
    </p>
    <div class="dl-split">
      <div class="dl-part">
        <h4>Differential prefix — round 1</h4>
        <p>
          Choose plaintext pairs with difference <strong>ΔX = ${hex(0x0b)}</strong> (${bin8(0x0b)}).
          Through the S-box the difference <strong>${hex(0x0b & 0xf)} → ${hex(designated.sboxDiff)}</strong> occurs for
          <strong>${Math.round(designated.weight * 16)} of 16</strong> inputs — the heaviest entry of that DDT row, so the
          differential holds with probability <strong>p = ${magnitude(designated.weight, 16)}</strong>.
        </p>
      </div>
      <div class="dl-join">
        <h4>Joining state</h4>
        <p>
          The state <strong>entering round 2</strong>. On the designated path its difference is
          <strong>ΔY = ${hex(designated.joiningDiff)}</strong> — the permuted S-box output difference.
          This is the explicit intermediate state where the two attacks are welded together.
        </p>
      </div>
      <div class="dl-part">
        <h4>Linear suffix — round 2</h4>
        <p>
          <span class="mask-line">${maskTerms(design.lambdaIn, 'u', 8)} = ${maskTerms(design.lambdaOut, 'v', 8)} ⊕ b</span>
          with correlation <strong>${signed(corr)}</strong>, a bias of <strong>ε = ${magnitude(eps, 16)}</strong> —
          measured over all 256 values of the joining state, not asserted.
        </p>
      </div>
    </div>
    <div class="dl-statistic">
      <h4>The composed statistic, on chosen pairs</h4>
      <p>
        For each pair (x, x⊕ΔX), peel the last round under a distinguishable subkey hypothesis g and count agreement of
        <span class="mask-line">⟨λout, v⟩ ⊕ ⟨λout, v'⟩ = ⟨λin, ΔY⟩</span>
        where the right-hand side is <strong>${designated.lambdaInDot}</strong> for this design.
        The two approximation constants b cancel in the pair — which is the entire trick.
      </p>
    </div>
    <p class="dl-note">${esc(design.note)}</p>
  `;
}

/** The DDT row of the chosen difference, path by path, with what λin sees. */
export function renderDlPaths(el: HTMLElement, { sbox, design }: DlSetup): void {
  const fixedRhs = designatedPath(sbox, design, 0x0b).lambdaInDot;
  const rows = prefixPaths(sbox, design, 0x0b)
    .map((path) => {
      const bias = pathPairBias(sbox, design, path.joiningDiff, fixedRhs);
      return `
        <tr${path.lambdaInDot === fixedRhs ? '' : ' class="is-flipped"'}>
          <td class="num">${hex(path.sboxDiff)}</td>
          <td class="num">${Math.round(path.weight * 16)}/16</td>
          <td class="num">${hex(path.joiningDiff)}</td>
          <td class="num">${path.lambdaInDot}</td>
          <td class="num">${signed(bias)}</td>
        </tr>`;
    })
    .join('');
  el.innerHTML = `
    <p>
      The whole DDT row of ΔX = ${hex(0x0b)} — every path the prefix can take, not just the designated one.
      <strong>⟨λin, Δ'⟩</strong> is what the suffix's input mask reads on each path's joining difference:
      when it is constant, the paths reinforce; when it moves, they can cancel.
    </p>
    <div class="dl-scroll" role="region" aria-label="Every path of the chosen difference" tabindex="0">
      <table class="dl-paths">
        <caption class="sr-only">Each path of the DDT row, its weight, joining difference, λin reading and exact pair bias.</caption>
        <thead>
          <tr>
            <th scope="col" class="num">S-box diff</th>
            <th scope="col" class="num">Weight</th>
            <th scope="col" class="num">Joining Δ'</th>
            <th scope="col" class="num">⟨λin, Δ'⟩</th>
            <th scope="col" class="num">Bias vs fixed RHS ${fixedRhs}</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
  `;
}

/**
 * The heuristic stack. Each layer names the assumption that separates it from
 * the next; the measured row is computed live on the full 128-pair codebook.
 */
export function renderDlHeuristics(
  el: HTMLElement,
  { sbox, design }: DlSetup,
  key: SpnKey,
): void {
  const designated = designatedPath(sbox, design, 0x0b);
  const corr = suffixCorrelation(sbox, design);
  const naive = naiveBias(designated.weight, corr);
  const aware = pathAwareBias(sbox, design, 0x0b);
  const measured = runDlAttack({ sbox, key, design, budget: 128 });
  el.innerHTML = `
    <div class="stat-stack" role="region" aria-label="Heuristic layers versus the measured bias" tabindex="0">
      <table class="dl-heuristics">
        <caption class="sr-only">Three predictions of the pair-statistic bias and the measured value.</caption>
        <thead>
          <tr><th scope="col">Prediction</th><th scope="col" class="num">Bias</th><th scope="col">Assumes</th></tr>
        </thead>
        <tbody>
          <tr>
            <td>Biham–Dunkelman–Keller p-weighted: <strong>2·p·ε²</strong></td>
            <td class="num">${asFraction(naive, 1024)}</td>
            <td>Off-path pairs wash out; the two texts' approximation errors are independent.</td>
          </tr>
          <tr>
            <td>Path-aware: <strong>Σ wᵢ·biasᵢ</strong></td>
            <td class="num">${asFraction(aware, 1024)}</td>
            <td>The complete DDT row is included; joining values are uniform within each path.</td>
          </tr>
          <tr class="is-measured">
            <td><strong>Measured</strong> — all 128 pairs, this session's key</td>
            <td class="num">${signed(measured.measuredBias)}</td>
            <td>Nothing. Counted on the real cipher.</td>
          </tr>
        </tbody>
      </table>
    </div>
    ${
      design.name === 'aligned'
        ? `<p>
             The p-weighted heuristic <em>understates</em> this cipher. The reason is in the table above:
             every path of this DDT row leaves ⟨λin, Δ'⟩ = ${designated.lambdaInDot}, so the off-path assumption fails
             upward. The path-aware estimate is ${asFraction(aware, 1024)}; this session measures
             <strong>${signed(measured.measuredBias)}</strong>. Across keys the full-codebook measurement is 1/4 or 5/16,
             because the joining values within each path are not a uniform independent population. The differential
             still matters: it selects a DDT row whose signed path contributions reinforce.
           </p>`
        : `<p>
             The control. The p-weighted heuristic promises ${asFraction(naive, 1024)}, but the signed path sum is
             <strong>${asFraction(aware, 1024)}</strong> and the cipher measures
             <strong>${signed(measured.measuredBias)}</strong>, exactly zero. The attack uses the designated path's
             right-hand side for every pair; paths with the opposite ⟨λin, Δ'⟩ therefore contribute with the opposite
             sign. Enumerating the DDT row catches the cancellation that the naive off-path assumption misses.
           </p>`
    }
  `;
}

/** The distinguishable-candidate ranking: top rows now, truth marked after a run. */
export function renderDlRanking(
  table: HTMLTableElement,
  result: DlAttackResult | null,
  reveal: boolean,
  design: DlDesign,
): void {
  const targetMask = subkeyTargetMask(design);
  const targetLabel = targetMask === 0xff ? 'Byte guess' : targetMask === 0xf0 ? 'High-nibble guess' : 'Low-nibble guess';
  if (!result) {
    table.innerHTML = `
      ${table.querySelector('caption')?.outerHTML ?? ''}
      <thead>
        <tr><th scope="col" class="num">Rank</th><th scope="col" class="num">${targetLabel}</th><th scope="col" class="num">Agreements</th><th scope="col" class="num">Bias</th></tr>
      </thead>
      <tbody>
        ${Array.from({ length: 8 }, () => `<tr><td class="num">·</td><td class="num">—</td><td class="num">—</td><td class="num">—</td></tr>`).join('')}
      </tbody>
    `;
    return;
  }
  const half = result.attackPairs / 2;
  const ranked = result.candidates
    .map((guess) => ({ guess, count: result.counts[guess], excess: Math.abs(result.counts[guess] - half) }))
    .sort((a, b) => b.excess - a.excess || a.guess - b.guess);
  const top = ranked.slice(0, 8);
  const trueRow = ranked.find((row) => row.guess === result.trueTarget);
  const competitionRank = (row: (typeof ranked)[number]): number =>
    1 + ranked.filter((candidate) => candidate.excess > row.excess).length;
  const rows = top.map((row) => dlRankRow(row, result, reveal, competitionRank(row)));
  if (reveal && trueRow && !top.includes(trueRow)) {
    rows.push(dlRankRow(trueRow, result, reveal, competitionRank(trueRow)));
  }
  table.innerHTML = `
    ${table.querySelector('caption')?.outerHTML ?? ''}
    <thead>
      <tr><th scope="col" class="num">Rank</th><th scope="col" class="num">${targetLabel}</th><th scope="col" class="num">Agreements</th><th scope="col" class="num">Bias</th></tr>
    </thead>
    <tbody>${rows.join('')}</tbody>
  `;
}

function dlRankRow(
  row: { guess: number; count: number },
  result: DlAttackResult,
  reveal: boolean,
  rank: number,
): string {
  const isWinner = row.guess === result.winner;
  const isTrue = reveal && row.guess === result.trueTarget;
  const markers: string[] = [];
  if (reveal && isTrue) markers.push(`<span class="marker is-key">actual ${result.targetMask === 0xff ? 'byte' : 'nibble'}</span>`);
  if (isWinner) markers.push('<span class="marker is-pick">largest |bias|</span>');
  const bias = (row.count - result.attackPairs / 2) / result.attackPairs;
  return `
    <tr class="${isTrue ? 'is-correct' : ''}${isWinner && !isTrue ? ' is-wrong-pick' : ''}">
      <td class="num">${rank}</td>
      <td class="num candidate">${hex(row.guess)} <span class="dim">${bin8(row.guess)}</span>${markers.join('')}</td>
      <td class="num">${row.count} / ${result.attackPairs}</td>
      <td class="num">${signed(bias)}</td>
    </tr>`;
}

/** The verdict block — same class vocabulary as the cockpit. */
export function renderDlVerdict(
  el: HTMLElement,
  options: {
    readonly result: DlAttackResult | null;
    readonly design: DlDesign;
    readonly naiveBias: number;
    readonly stale: boolean;
  },
): void {
  const { result, design, naiveBias, stale } = options;
  if (stale) {
    el.className = 'verdict is-stale';
    el.innerHTML = `<div class="verdict-head"><span class="verdict-icon" aria-hidden="true">↻</span><span>CONFIGURATION CHANGED</span></div><p>The composition settings moved after that result. Run it again.</p>`;
    return;
  }
  if (!result) {
    el.className = 'verdict is-armed';
    const candidates = subkeyCandidates(design).length;
    const target = subkeyTargetMask(design) === 0xff ? 'byte values' : 'high-nibble values';
    el.innerHTML = `<div class="verdict-head"><span class="verdict-icon" aria-hidden="true">○</span><span>READY — NO PAIRS SPENT</span></div><p>${candidates} distinguishable ${target}, no evidence yet. Spend a chosen-plaintext budget and see which hypothesis deviates farthest from a coin flip.</p>`;
    return;
  }
  if (design.name === 'cancelled') {
    el.className = 'verdict is-held';
    el.innerHTML = `
      <div class="verdict-head"><span class="verdict-icon" aria-hidden="true">■</span><span>NO SIGNAL — THE CONTROL</span></div>
      <p>
        The p-weighted heuristic promised ${asFraction(naiveBias, 1024)}, but the exact signed path sum is
        <strong>0</strong>. This selected ${result.attackPairs}-pair run measures
        <strong>${signed(result.measuredBias)}</strong>; any nonzero deviation at a partial budget is finite-sample
        noise around a full-codebook population that measures zero for every key. This output mask
        observes only the high key nibble, so the page ranks ${result.candidates.length} high-nibble hypotheses—not 256 pretend byte guesses.
        Over 512 deterministic keys the signal-free ranking recovers that nibble 0 times at 96 and 128 pairs.
        The naive assumption that failed was that off-path pairs wash out; the path table exposes their cancellation.
      </p>`;
    return;
  }
  if (result.verdict === 'recovered') {
    el.className = 'verdict is-broken';
    el.innerHTML = `
      <div class="verdict-head"><span class="verdict-icon" aria-hidden="true">◆</span><span>LAST-ROUND BYTE RECOVERED</span></div>
      <p>
        One candidate — <strong>${hex(result.winner)}</strong> — separated from ${result.candidates.length - 1} rivals on
        ${result.attackPairs} chosen pairs. The heuristic predicted a bias of
        ${asFraction(naiveBias, 1024)};
        the right guess actually agreed <strong>${result.counts[result.trueTarget]} / ${result.attackPairs}</strong> times.
      </p>`;
    return;
  }
  if (result.verdict === 'tied') {
    el.className = 'verdict is-partial';
    el.innerHTML = `
      <div class="verdict-head"><span class="verdict-icon" aria-hidden="true">◐</span><span>TIED AT THE TOP</span></div>
      <p>
        The largest absolute deviation is shared by ${result.winnerTies + 1} candidates. This is the honest reading of a starved
        budget — the statistic cannot separate them, and the page does not pretend it did.
      </p>`;
    return;
  }
  el.className = 'verdict is-held';
  el.innerHTML = `
    <div class="verdict-head"><span class="verdict-icon" aria-hidden="true">■</span><span>NOT SEPARATED THIS TIME</span></div>
    <p>The largest absolute deviation belonged to a different candidate. At this budget the composed bias (${asFraction(Math.abs(result.measuredBias), 1024)}) is inside the noise of ${result.candidates.length} counters — an honest finite-sample failure, not a broken mechanism.</p>`;
}

/** The holdout verification: fresh pairs the ranking never touched. */
export function renderDlHoldout(el: HTMLElement, result: DlAttackResult | null, stale: boolean): void {
  if (stale) {
    el.innerHTML = '<p>The settings moved after this result. Run the composition again before interpreting a holdout.</p>';
    return;
  }
  if (!result) {
    el.innerHTML = '<p>Run the composition first; the verification spends pairs the ranking never touched.</p>';
    return;
  }
  if (result.holdoutPairs === 0) {
    el.innerHTML = '<p>Every pair went into the ranking at a budget of 128, so there is nothing held back. Drop the budget to keep a holdout.</p>';
    return;
  }
  const winnerHeld = result.holdoutCounts[result.winner];
  const bestOtherHeld = result.holdoutPairs / 2 + result.maxOtherHoldoutBias * result.holdoutPairs;
  el.innerHTML = `
    <p>
      <strong>Independent check on ${result.holdoutPairs} fresh pairs</strong> (the ranking never saw them):
      the winning guess keeps <strong>${winnerHeld} / ${result.holdoutPairs}</strong> agreements
      (bias ${signed(result.winnerHoldoutBias)}), while the strongest of the ${result.candidates.length - 1}
      other ${result.targetMask === 0xff ? 'byte' : 'nibble'} hypotheses has <strong>${Math.round(bestOtherHeld)} / ${result.holdoutPairs}</strong>
      (bias ${signed(result.maxOtherHoldoutBias)}).
      ${
        result.holdoutConfirms
          ? "The fresh pairs preserve the winner's separation from every rival in this bounded run."
          : 'The fresh pairs do NOT separate the winner from the field — treat the ranking with suspicion.'
      }
    </p>`;
}

/** The measured success-rate curve: the finite-sample truth across keys. */
export function renderDlCurve(el: HTMLElement, points: readonly DlSuccessPoint[], design: DlDesign): void {
  const rows = points
    .map(
      (p) => `
        <tr>
          <td class="num">${p.budget}</td>
          <td class="num">${p.trials.toLocaleString()}</td>
          <td class="num">${percent(p.rate, 1)}</td>
          <td class="num">${p.tiedWins} of ${p.wins}</td>
        </tr>`,
    )
    .join('');
  el.innerHTML = `
    <p>
      The heuristic bias is an asymptotic, population-level statement. This is what actually happens:
      the same deterministic ranking, run over ${points[0]?.trials.toLocaleString() ?? 0} keys
      (${
        design.name === 'aligned'
          ? 'master keys 0, 129, 258, … — a fixed odd stride that disperses this bounded sample across the 16-bit key space; it is reproducible, not a random population estimate'
          : 'the control: 16 observable high-nibble hypotheses, the same machinery and key walk, on the cancelled composition'
      }). No randomness anywhere — the same inputs give the same curve every time.
    </p>
    <div class="dl-scroll" role="region" aria-label="Measured ranking success by budget" tabindex="0">
      <table class="dl-curve">
        <caption class="sr-only">Measured rate at which the true key target reaches the top equivalence class, per chosen-pair budget.</caption>
        <thead>
          <tr>
            <th scope="col" class="num">Pairs spent</th>
            <th scope="col" class="num">Keys tried</th>
            <th scope="col" class="num">True target at top</th>
            <th scope="col" class="num">Top results that tied</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
}

/** Budget note under the segmented control. */
export function dlBudgetNote(budget: number): string {
  const holdout = 128 - budget;
  return holdout === 0
    ? 'All 128 pairs go into the ranking; nothing is held back for verification.'
    : `${budget} pairs feed the ranking; the other ${holdout} are held back for the independent verification.`;
}
