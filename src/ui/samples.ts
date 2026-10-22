import { finitePopulationCorrection, requiredSamples, theoreticalSuccessRate, wilsonInterval, type SuccessPoint } from '../crypto/attack.js';
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

/** Both sampling plans use the same 60 random keys at each data size. */
export function renderSamplingComparison(
  el: HTMLElement,
  repeated: readonly SuccessPoint[],
  distinct: readonly SuccessPoint[],
): void {
  const rateWithInterval = (point: SuccessPoint): string => {
    const [low, high] = wilsonInterval(point.outrightBreaks, point.trials);
    return `${percent(point.rate, 0)} <span class="control-note">(${percent(low, 0)}–${percent(high, 0)})</span>`;
  };
  const rows = repeated.map((withRepeats, i) => {
    const withoutRepeats = distinct[i];
    if (!withoutRepeats || withoutRepeats.samples !== withRepeats.samples || withoutRepeats.trials !== withRepeats.trials) {
      throw new Error('sampling comparison rows must have matching counts and trials');
    }
    return `<tr>
      <th scope="row" class="num">${withRepeats.samples}</th>
      <td class="num">${withRepeats.meanUnique.toFixed(1)} / ${withRepeats.samples}</td>
      <td class="num">${rateWithInterval(withRepeats)}</td>
      <td class="num">${withoutRepeats.meanUnique.toFixed(0)} / ${withoutRepeats.samples}</td>
      <td class="num">${rateWithInterval(withoutRepeats)}</td>
      <td class="num">${finitePopulationCorrection(256, withRepeats.samples).toFixed(3)}</td>
    </tr>`;
  }).join('');
  el.innerHTML = `
    <div class="curve-wrap" role="region" aria-label="Repeated versus distinct plaintext sampling" tabindex="0">
      <table class="curve">
        <caption class="sr-only">Attack success over ${repeated[0]?.trials ?? 0} toy keys per row, at equal sample counts.</caption>
        <thead><tr>
          <th scope="col">Pairs</th><th scope="col">Repeated: unique</th><th scope="col">Repeated: success (95% interval)</th>
          <th scope="col">Distinct: unique</th><th scope="col">Distinct: success (95% interval)</th>
          <th scope="col">Variance factor</th>
        </tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
    <p class="control-note">These are complete key-ranking attacks over the same ${repeated[0]?.trials ?? 0} random toy keys per row.
      The parenthesized Wilson intervals describe uncertainty in the measured <em>across-key success proportion</em>,
      not a guarantee for any key or a proof against a real cipher. Distinct traffic is sampled randomly from the
      256-plaintext codebook; it is not a chosen-plaintext oracle. At 256 distinct pairs the entire codebook is seen.</p>
    <p class="control-note">For a fixed key with a relation that holds on fraction <em>p</em> of the codebook,
      the count variance for N distinct draws is Np(1−p) × (256−N)/255 versus Np(1−p) for draws with replacement.
      The final column is this finite-population factor; at N=256 it is zero. It describes a single counter’s
      sampling variance, not the variance of attack success across keys or the ranking of 16 candidates.
      <a href="https://www.cambridge.org/core/books/abs/linear-cryptanalysis/statistics-of-linear-cryptanalysis/4233F6B7EFEC3E49BDE1958049BAA16C" target="_blank" rel="noopener noreferrer">Beyne and Rijmen, <cite>Linear Cryptanalysis</cite> (2025), ch. 4</a>.</p>
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
