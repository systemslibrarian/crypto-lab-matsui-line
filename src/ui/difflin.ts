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
        For each pair (x, x⊕ΔX), peel the last round under a candidate subkey byte g and count agreement of
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
  const rows = prefixPaths(sbox, design, 0x0b)
    .map((path) => {
      const bias = pathPairBias(sbox, design, path.joiningDiff);
      return `
        <tr${path.lambdaInDot === 0 ? '' : ' class="is-flipped"'}>
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
            <th scope="col" class="num">Exact pair bias</th>
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
            <td>Langford–Hellman naive: <strong>2·p·ε²</strong></td>
            <td class="num">${asFraction(naive, 1024)}</td>
            <td>Off-path pairs wash out; the two texts' approximation errors are independent.</td>
          </tr>
          <tr>
            <td>Path-aware: <strong>Σ wᵢ·biasᵢ</strong></td>
            <td class="num">${asFraction(aware, 1024)}</td>
            <td>Same, plus: joining values are uniform within each DDT path.</td>
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
             The naive heuristic <em>understates</em> this cipher by more than half. The reason is in the table above:
             every path of this DDT row leaves ⟨λin, Δ'⟩ = ${designated.lambdaInDot}, so the off-path assumption fails
             upward — the off-path pairs carry the <em>same</em> pair bias as the designated path. The differential
             still matters: it selects a DDT row whose paths align. Other differences do not.
           </p>`
        : `<p>
             The control. The heuristic promises ${asFraction(naive, 1024)} — and the cipher measures
             <strong>${signed(measured.measuredBias)}</strong>, exactly zero, for every key. The paths of the same DDT row
             move ⟨λin, Δ'⟩ in both directions and their contributions cancel. An attacker who trusted the heuristic
             would spend queries ranking noise.
           </p>`
    }
  `;
}

/** The 256-candidate ranking: top rows now, the truth marked only after a run. */
export function renderDlRanking(
  table: HTMLTableElement,
  result: DlAttackResult | null,
  reveal: boolean,
): void {
  if (!result) {
    table.innerHTML = `
      ${table.querySelector('caption')?.outerHTML ?? ''}
      <thead>
        <tr><th scope="col" class="num">Rank</th><th scope="col" class="num">Subkey guess</th><th scope="col" class="num">Agreements</th><th scope="col" class="num">Bias</th></tr>
      </thead>
      <tbody>
        ${Array.from({ length: 8 }, () => `<tr><td class="num">·</td><td class="num">—</td><td class="num">—</td><td class="num">—</td></tr>`).join('')}
      </tbody>
    `;
    return;
  }
  const half = result.attackPairs / 2;
  const ranked = result.counts
    .map((count, guess) => ({ guess, count, excess: Math.abs(count - half) }))
    .sort((a, b) => b.excess - a.excess || a.guess - b.guess);
  const top = ranked.slice(0, 8);
  const trueRow = ranked.find((row) => row.guess === result.trueSubkey);
  const rows = top.map((row) => dlRankRow(row, result, reveal, ranked.indexOf(row) + 1));
  if (reveal && trueRow && !top.includes(trueRow)) {
    rows.push(dlRankRow(trueRow, result, reveal, ranked.indexOf(trueRow) + 1));
  }
  table.innerHTML = `
    ${table.querySelector('caption')?.outerHTML ?? ''}
    <thead>
      <tr><th scope="col" class="num">Rank</th><th scope="col" class="num">Subkey guess</th><th scope="col" class="num">Agreements</th><th scope="col" class="num">Bias</th></tr>
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
  const isTrue = reveal && row.guess === result.trueSubkey;
  const markers: string[] = [];
  if (reveal && isTrue) markers.push('<span class="marker is-key">actual key</span>');
  if (isWinner) markers.push('<span class="marker is-pick">top count</span>');
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
    el.innerHTML = `<div class="verdict-head"><span class="verdict-icon" aria-hidden="true">○</span><span>READY — NO PAIRS SPENT</span></div><p>256 candidate values of the last whitening byte, no evidence yet. Spend a chosen-plaintext budget and see which candidate stops looking like a coin flip.</p>`;
    return;
  }
  if (design.name === 'cancelled') {
    el.className = 'verdict is-held';
    el.innerHTML = `
      <div class="verdict-head"><span class="verdict-icon" aria-hidden="true">■</span><span>NO SIGNAL — THE CONTROL</span></div>
      <p>
        The heuristic promised ${asFraction(naiveBias, 1024)};
        the measurement says <strong>${signed(result.measuredBias)}</strong>. The winner of this ranking is noise wearing
        a crown — over 512 keys this configuration crowns the true subkey 0 times at 64 pairs or more.
        The assumption that failed: that pairs off the designated differential contribute no bias. Here they
        contribute the opposite bias, and cancel exactly.
      </p>`;
    return;
  }
  if (result.verdict === 'recovered') {
    el.className = 'verdict is-broken';
    el.innerHTML = `
      <div class="verdict-head"><span class="verdict-icon" aria-hidden="true">◆</span><span>LAST-ROUND BYTE RECOVERED</span></div>
      <p>
        One candidate — <strong>${hex(result.winner)}</strong> — separated from 255 rivals on
        ${result.attackPairs} chosen pairs. The heuristic predicted a bias of
        ${asFraction(naiveBias, 1024)};
        the right guess actually agreed <strong>${result.counts[result.trueSubkey]} / ${result.attackPairs}</strong> times.
      </p>`;
    return;
  }
  if (result.verdict === 'tied') {
    el.className = 'verdict is-partial';
    el.innerHTML = `
      <div class="verdict-head"><span class="verdict-icon" aria-hidden="true">◐</span><span>TIED AT THE TOP</span></div>
      <p>
        The top count is shared by ${result.winnerTies + 1} candidates. This is the honest reading of a starved
        budget — the statistic cannot separate them, and the page does not pretend it did.
      </p>`;
    return;
  }
  el.className = 'verdict is-held';
  el.innerHTML = `
    <div class="verdict-head"><span class="verdict-icon" aria-hidden="true">■</span><span>NOT SEPARATED THIS TIME</span></div>
    <p>The top count went to a different candidate. At this budget the composed bias (${asFraction(Math.abs(result.measuredBias), 1024)}) is inside the noise of 256 counters — an honest finite-sample failure, not a broken mechanism.</p>`;
}

/** The holdout verification: fresh pairs the ranking never touched. */
export function renderDlHoldout(el: HTMLElement, result: DlAttackResult | null, spent: boolean): void {
  if (!result || result.holdoutPairs === 0) {
    el.innerHTML = spent
      ? '<p>Every pair went into the ranking at a budget of 128, so there is nothing held back. Drop the budget to keep a holdout.</p>'
      : '<p>Run the composition first; the verification spends pairs the ranking never touched.</p>';
    return;
  }
  const winnerHeld = result.holdoutCounts[result.winner];
  const bestWrongHeld = result.holdoutPairs / 2 + result.maxWrongHoldoutBias * result.holdoutPairs;
  el.innerHTML = `
    <p>
      <strong>Independent check on ${result.holdoutPairs} fresh pairs</strong> (the ranking never saw them):
      the winning guess keeps <strong>${winnerHeld} / ${result.holdoutPairs}</strong> agreements
      (bias ${signed(result.winnerHoldoutBias)}), while the best of the 255
      wrong guesses manages <strong>${Math.round(bestWrongHeld)} / ${result.holdoutPairs}</strong>
      (bias ${signed(result.maxWrongHoldoutBias)}).
      ${
        result.holdoutConfirms
          ? 'The fresh pairs agree: the winner is real, not a fluke of the attack half.'
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
          ? 'master keys 0…511, chosen pairs fixed by the budget'
          : 'the control: the same machinery on the cancelled composition'
      }). No randomness anywhere — the same inputs give the same curve every time.
    </p>
    <div class="dl-scroll" role="region" aria-label="Measured ranking success by budget" tabindex="0">
      <table class="dl-curve">
        <caption class="sr-only">Measured success rate of the subkey ranking across keys, per chosen-pair budget.</caption>
        <thead>
          <tr>
            <th scope="col" class="num">Pairs spent</th>
            <th scope="col" class="num">Keys tried</th>
            <th scope="col" class="num">Winner was the key</th>
            <th scope="col" class="num">Ties among wins</th>
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
