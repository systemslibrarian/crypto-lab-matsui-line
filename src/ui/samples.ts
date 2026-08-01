import { requiredSamples, theoreticalSuccessRate, type SuccessPoint } from '../crypto/attack.js';
import { asFraction, percent } from './format.js';

/**
 * Matsui's sample-size rule, applied to whatever approximation is currently
 * loaded. The headline number is 1/ε² because that is the one people quote;
 * the surrounding tiles say what it actually buys you.
 */
export function renderCalculator(el: HTMLElement, bias: number, currentSamples: number): void {
  const inverseSquare = Math.round(1 / (bias * bias));
  const at977 = requiredSamples(bias, 0.977);
  const at999 = requiredSamples(bias, 0.999);
  const now = theoreticalSuccessRate(bias, currentSamples);

  el.innerHTML = `
    <div class="stat">
      <span class="stat-label">Current bias ε</span>
      <span class="stat-value">${asFraction(bias, 4096)}</span>
      <span class="stat-note">${Math.abs(bias).toFixed(5)} — the leak the attack is listening for.</span>
    </div>
    <div class="stat">
      <span class="stat-label">Matsui's rule: 1 / ε²</span>
      <span class="stat-value">${inverseSquare.toLocaleString()}</span>
      <span class="stat-note">Known plaintexts for a 97.7% chance of reading one counter correctly.</span>
    </div>
    <div class="stat">
      <span class="stat-label">For 97.7% / 99.9%</span>
      <span class="stat-value">${at977.toLocaleString()} / ${at999.toLocaleString()}</span>
      <span class="stat-note">N = (Φ⁻¹(p) / 2ε)². Ten times the confidence costs about four times the traffic.</span>
    </div>
    <div class="stat">
      <span class="stat-label">At your current ${currentSamples.toLocaleString()}</span>
      <span class="stat-value">${percent(now, 1)}</span>
      <span class="stat-note">What the formula promises. The measurement below is the honest number.</span>
    </div>
  `;
}

/**
 * Measured success rate against the formula's prediction. The gap is the
 * point: the formula describes one counter reading correctly, the attack needs
 * one counter to beat fifteen rivals.
 */
export function renderCurve(el: HTMLElement, points: readonly SuccessPoint[]): void {
  const rows = points
    .map(
      (p) => `
        <tr>
          <td class="num">${p.samples.toLocaleString()}</td>
          <td class="num">${percent(p.rate, 0)}</td>
          <td class="num">${percent(p.theoretical, 1)}</td>
          <td>
            <div class="dual-bar">
              <span class="measured" style="width:${Math.max(1, p.rate * 100)}%"></span>
              <span class="theory" style="width:${Math.max(1, p.theoretical * 100)}%"></span>
            </div>
          </td>
        </tr>`,
    )
    .join('');

  el.innerHTML = `
    <div class="curve-wrap" role="region" aria-label="Measured versus predicted success rate" tabindex="0">
      <table class="curve">
        <caption class="sr-only">
          Measured attack success rate compared with the theoretical single-counter prediction, by number of known
          plaintexts.
        </caption>
        <thead>
          <tr>
            <th scope="col">Known plaintexts</th>
            <th scope="col">Measured</th>
            <th scope="col">Formula</th>
            <th scope="col">Comparison</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
    <div class="legend">
      <span><span class="swatch measured" aria-hidden="true"></span> Measured — the attack actually run, ${points[0].trials} keys per row</span>
      <span><span class="swatch theory" aria-hidden="true"></span> Formula — Matsui's single-counter prediction</span>
    </div>
    <p class="control-note">
      The formula runs ahead of reality everywhere, and that is expected rather than a discrepancy to explain away: it
      answers "will this counter lean the right way?", while the attack has to ask "will this counter out-lean fifteen
      others?". Ranking is the harder question, so it costs more data. ${costNote(points)}
    </p>
  `;
}

/**
 * Compare the two curves at the same bar rather than at whichever points
 * flatter the story — and say plainly when the measurement never got there.
 */
function costNote(points: readonly SuccessPoint[], target = 0.9): number | string {
  const formulaHit = points.find((p) => p.theoretical >= target);
  const measuredHit = points.find((p) => p.rate >= target);
  const pct = `${Math.round(target * 100)}%`;
  if (!formulaHit) return `Neither curve reached ${pct} over the sizes measured.`;
  if (!measuredHit) {
    const last = points[points.length - 1];
    return `The formula clears ${pct} at ${formulaHit.samples.toLocaleString()} known plaintexts; the attack was still at
      ${percent(last.rate, 0)} with ${last.samples.toLocaleString()} — more than ${Math.round(last.samples / formulaHit.samples)}× the data, and not there yet.`;
  }
  const ratio = measuredHit.samples / formulaHit.samples;
  return `The formula clears ${pct} at ${formulaHit.samples.toLocaleString()} known plaintexts; the attack actually got
    there at ${measuredHit.samples.toLocaleString()} — about ${ratio < 1.5 ? 'the same' : `${Math.round(ratio)}×`} ${ratio < 1.5 ? 'amount' : 'more'}.`;
}
