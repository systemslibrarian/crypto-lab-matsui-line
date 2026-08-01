import type { Sbox } from '../crypto/sbox.js';
import type { SpnKey } from '../crypto/spn.js';
import { biasAcrossKeys, exactBias, pilingUpBias, type Trail } from '../crypto/trail.js';
import { asFraction, bin4, esc, magnitude, maskTerms, percent, signed } from './format.js';

/** Bar scaled against the largest bias a single approximation can have (1/2). */
function biasBar(bias: number): string {
  const width = Math.min(50, Math.abs(bias) * 100);
  const negative = bias < 0;
  const style = negative ? `right:50%;left:auto;width:${width}%` : `left:50%;width:${width}%`;
  return `<div class="bias-bar"><div class="bias-bar-axis"></div><div class="bias-bar-fill${negative ? ' is-negative' : ''}" style="${style}"></div></div>`;
}

/**
 * One card per round of the trail, revealed a round at a time. Rounds not yet
 * revealed are drawn dashed and empty so the shrinking is something you watch
 * happen rather than something you are told about.
 */
export function renderTrailSteps(list: HTMLElement, trail: Trail, revealed: number): void {
  list.innerHTML = trail.steps
    .map((step, index) => {
      const pending = index >= revealed;
      const active = step.nibbles.filter((n) => n.active);
      const body = pending
        ? '<div class="piling-round-body">— not yet applied —</div>'
        : `
          <div class="piling-round-body">
            ${maskTerms(step.inMask, 'U', 8)} &nbsp;→&nbsp; ${maskTerms(step.sboxOutMask, 'V', 8)}
          </div>
          <div class="piling-round-body">
            ${active
              .map(
                (n) =>
                  `<span class="nibble-note">${n.half === 'high' ? 'high' : 'low'} S-box ${bin4(n.inMask)}→${bin4(n.outMask)}: correlation ${signed(n.correlation, 3)}</span>`,
              )
              .join('<br />')}
          </div>
          ${biasBar(step.bias)}`;
      return `
        <li class="piling-round${pending ? ' is-pending' : ''}">
          <div class="piling-round-head">
            <span>Round ${step.round}</span>
            <span>${pending ? '' : `ε<sub>${step.round}</sub> = ${asFraction(step.bias, 16)} (${signed(step.bias)})`}</span>
          </div>
          ${body}
        </li>`;
    })
    .join('');
}

export function renderPilingResult(el: HTMLElement, trail: Trail, revealed: number): void {
  const biases = trail.steps.slice(0, revealed).map((s) => s.bias);
  const running = revealed === 0 ? 0.5 : pilingUpBias(biases);
  const n = Math.max(biases.length, 1);
  const product = biases.map((b) => asFraction(b, 16)).join(' × ') || '—';

  el.innerHTML = `
    <span class="stat-label">Bias after ${revealed} of ${trail.steps.length} rounds</span>
    <span class="big-number">${revealed === 0 ? '1/2' : asFraction(running, 4096)}</span>
    <p class="control-note">
      ${
        revealed === 0
          ? 'Nothing applied yet: a relation you have not constrained is a coin flip, bias 1/2 away from nothing — it holds every time only because it says nothing.'
          : `The relation holds ${percent(0.5 + Math.abs(running), 2)} of the time instead of 50%.`
      }
    </p>
    <p class="formula">ε = 2<sup>${n - 1}</sup> × ${product} = ${signed(running, 5)}</p>
    ${
      revealed > 0
        ? `<p class="control-note">Equivalently, correlations multiply: ${trail.steps
            .slice(0, revealed)
            .map((s) => signed(s.correlation, 3))
            .join(' × ')} = ${signed(running * 2, 5)}.</p>`
        : ''
    }
    ${
      revealed === trail.steps.length
        ? `<p class="control-note"><strong>${trail.activeSboxes} active S-boxes.</strong> Each one costs you: the more S-boxes a trail has to cross, the smaller what comes out the other end. That is the whole design principle behind round counts.</p>`
        : ''
    }
  `;
}

export interface DecayPoint {
  readonly layers: number;
  readonly bias: number;
  readonly samplesNeeded: number;
}

/**
 * The decay curve: the best bias *any* trail can reach over 1, 2 and 3 S-box
 * layers, and what each costs in traffic. This is the argument for round
 * counts in one strip — each round roughly halves the bias, and halving the
 * bias quadruples the data.
 */
export function renderDecay(el: HTMLElement, points: readonly DecayPoint[]): void {
  const widest = Math.max(...points.map((p) => Math.abs(p.bias)));
  el.innerHTML = `
    <table class="decay">
      <caption class="sr-only">Best achievable bias and the traffic it demands, by number of S-box layers crossed.</caption>
      <thead>
        <tr>
          <th scope="col">Rounds crossed</th>
          <th scope="col">Best bias available</th>
          <th scope="col">Known plaintexts needed</th>
          <th scope="col">Strength</th>
        </tr>
      </thead>
      <tbody>
        ${points
          .map(
            (p) => `<tr>
              <th scope="row">${p.layers}</th>
              <td class="num">${magnitude(p.bias, 4096)}</td>
              <td class="num">${Number.isFinite(p.samplesNeeded) ? p.samplesNeeded.toLocaleString() : '∞'}</td>
              <td><div class="rank-bar" style="width:${Math.max(2, (Math.abs(p.bias) / widest) * 100)}%"></div></td>
            </tr>`,
          )
          .join('')}
      </tbody>
    </table>
    <p class="control-note">
      Each extra round roughly halves the best bias on offer, and because the data requirement goes as 1/ε², halving the
      bias quadruples the traffic. Run that forward far enough and the attack needs more plaintext than the cipher will
      ever encrypt — which is the entire defence, and the reason AES has ten rounds rather than four.
    </p>
  `;
}

/**
 * The piling-up lemma assumes the rounds are independent. They are not, quite.
 * This panel puts the lemma's prediction next to the bias measured by running
 * the real cipher over its entire codebook — for this key, and for others.
 */
export function renderTrailTruth(
  el: HTMLElement,
  sbox: Sbox,
  key: SpnKey,
  cipherRounds: number,
  trail: Trail,
): void {
  const measured = exactBias(sbox, key, cipherRounds, trail.startMask, trail.endMask);
  const spread = biasAcrossKeys(sbox, cipherRounds, trail.startMask, trail.endMask, [
    0x0000, 0x1234, 0x3a94, 0x5a5a, 0x77f0, 0x9c3d, 0xace1, 0xbeef, 0xd471, 0xffff,
  ]);
  const magnitudes = spread.map(Math.abs);
  const min = Math.min(...magnitudes);
  const max = Math.max(...magnitudes);
  const exact = Math.abs(max - min) < 1e-12 && Math.abs(max - Math.abs(trail.bias)) < 1e-12;

  el.innerHTML = `
    <p>
      The lemma predicts a magnitude of <strong>${magnitude(trail.bias, 4096)}</strong>. Running this cipher on all 256
      plaintexts under the current key gives <strong>${magnitude(measured, 256)}</strong> (${signed(measured)}).
    </p>
    <p>
      ${
        exact
          ? `Across ten different keys the magnitude is <strong>always ${magnitude(max, 256)}</strong> — only the sign
             moves. With a single trail dominating, the lemma is not an approximation here, it is exact. The round
             keys can flip which way the relation leans, and that is all they can do.`
          : `Across ten different keys the measured magnitude ranges from <strong>${magnitude(min, 256)}</strong> to
             <strong>${magnitude(max, 256)}</strong>. The prediction is a useful estimate and nothing stronger: many
             trails join the same pair of masks, and for any given key they reinforce or cancel. This is the
             <dfn>linear hull</dfn> effect, and it is why a serious analysis measures rather than assumes.
             ${
               min === 0
                 ? `<strong>For one of these keys the cancellation is total</strong> — the true bias is exactly 0, so
                    against that key this approximation is worthless no matter how much traffic you collect, while the
                    lemma goes on predicting ${magnitude(trail.bias, 4096)}.`
                 : ''
             }`
      }
    </p>
    <p class="control-note">
      ${esc(
        spread
          .map((b, i) => `key ${i + 1}: ${signed(b, 4)}`)
          .join('  ·  '),
      )}
    </p>
  `;
}
