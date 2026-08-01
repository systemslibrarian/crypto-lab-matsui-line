import type { AttackResult, SelectedApproximation } from '../crypto/attack.js';
import type { NibbleHalf } from '../crypto/spn.js';
import type { Trail } from '../crypto/trail.js';
import { asFraction, bin4, esc, hexNibble, magnitude, maskTerms, percent, plural, signed } from './format.js';

function magnitudeOf(trail: Trail | null): string {
  return trail ? magnitude(trail.bias, 4096) : '0';
}

export interface VerdictContext {
  readonly half: NibbleHalf;
  readonly cipherRounds: number;
  readonly samples: number;
  readonly trail: Trail | null;
  readonly wholeCodebook: boolean;
  /** Whether screening found an approximation that always names this nibble. */
  readonly usable: boolean | null;
  /** Fraction of screened keys this approximation named outright, if screened. */
  readonly ceiling: number | null;
}

/**
 * Colour tracks the integrity of the CIPHER, not the success of the button:
 * a recovered key is an alarm, because something that should have been secret
 * is on the screen. Every state also carries an icon and a word, so none of it
 * depends on being able to see the colour.
 */
export function renderVerdict(el: HTMLElement, result: AttackResult, ctx: VerdictContext): void {
  const half = ctx.half === 'high' ? 'bits 7…4' : 'bits 3…0';
  const source = ctx.wholeCodebook
    ? 'all 256 plaintexts (the entire codebook — no sampling error at all)'
    : `${ctx.samples.toLocaleString()} known ${plural(ctx.samples, 'plaintext')}`;

  let cls: string;
  let icon: string;
  let headline: string;
  let body: string;

  if (result.recovered) {
    cls = 'is-broken';
    icon = '⚠';
    headline = `KEY RECOVERED — subkey nibble ${half} is ${hexNibble(result.trueNibble)}`;
    body = `From ${source} and nothing else, the counter for candidate <code>${bin4(result.trueNibble)}</code> deviated
      furthest from a coin flip (${signed(result.scores[result.trueNibble].bias)}), and it is the real key. Four bits of
      the ${ctx.cipherRounds}-round cipher's final subkey are now public. The attacker never chose a plaintext and never
      touched the key.${
        ctx.usable === false && ctx.ceiling !== null
          ? ` <strong>Do not read too much into this one.</strong> Screening this approximation across a spread of keys
             named the right candidate only ${percent(ctx.ceiling, 0)} of the time — this key was one of the ones it
             works on. Press <em>New key</em> and run it again; it will not always land.`
          : ''
      }`;
  } else if (result.tiedAtTop) {
    cls = 'is-partial';
    icon = '≈';
    headline = `PARTIAL — ${result.winners.length} candidates tied at the top`;
    body = `The correct value is among them, so the search space fell from 16 to ${result.winners.length}
      (${result.bitsRecovered} of 4 bits), but this approximation cannot separate the survivors. More data will not help:
      the tie is structural, not statistical. That is a real outcome of linear cryptanalysis, and pretending otherwise
      would be the lie.`;
  } else {
    cls = 'is-held';
    icon = '✓';
    const bestWrong = Math.max(
      ...result.scores.filter((s) => s.guess !== result.trueNibble).map((s) => s.deviation),
    );
    const correct = result.scores[result.trueNibble].deviation;
    headline = `NOT RECOVERED — the real key ranked #${result.correctRank} of 16`;
    body = `The top-ranked candidate ${hexNibble(result.ranked[0].guess)} is wrong. Working from ${source}, the real
      key's counter reached ${signed(correct)} while the loudest wrong guess reached ${signed(bestWrong)} — the signal
      never got clear of the impostors. ${
        ctx.wholeCodebook
          ? `And there is no more data to collect: every one of the 256 possible plaintexts is already in the count, so
             this is the ceiling for this approximation, not a run of bad luck.`
          : 'More traffic may still fix this one — the counters are noisy, not tied.'
      }${
        ctx.cipherRounds === 4
          ? ` Four rounds is where this toy stops falling to a single linear approximation: the best trail the search
             can find over three rounds is biased by only ${magnitudeOf(ctx.trail)}, which on a 256-plaintext codebook
             is the same order as the noise a wrong guess makes on its own.`
          : ''
      }${
        ctx.usable === false
          ? ` Screening agrees: no approximation in the ranking separates the ${ctx.half} nibble cleanly, so this is a
             property of the cipher rather than a bad roll.`
          : ''
      }`;
  }

  el.className = `verdict ${cls}`;
  el.innerHTML = `
    <div class="verdict-head"><span class="verdict-icon" aria-hidden="true">${icon}</span><span>${esc(headline)}</span></div>
    <p>${body}</p>
  `;
}

export function renderRanking(table: HTMLTableElement, result: AttackResult): void {
  const top = Math.max(...result.scores.map((s) => s.deviation), 1e-9);
  const rows = result.ranked
    .map((score, index) => {
      const isCorrect = score.guess === result.trueNibble;
      const width = Math.max(1, (score.deviation / top) * 100);
      const markers = [
        isCorrect ? '<span class="marker is-key">actual key</span>' : '',
        index === 0 && !isCorrect ? '<span class="marker is-pick">attack picked</span>' : '',
        index === 0 && isCorrect ? '<span class="marker is-pick">attack picked</span>' : '',
      ].join('');
      return `
        <tr class="${isCorrect ? 'is-correct' : ''}">
          <td class="num">${index + 1}</td>
          <td class="num">${hexNibble(score.guess)} <span class="control-note">${bin4(score.guess)}</span>${markers}</td>
          <td class="num">${score.matches.toLocaleString()} / ${score.total.toLocaleString()}</td>
          <td class="num">${signed(score.bias)}</td>
          <td class="bar-cell"><div class="rank-bar" style="width:${width}%"></div></td>
        </tr>`;
    })
    .join('');

  table.innerHTML = `
    ${table.querySelector('caption')?.outerHTML ?? ''}
    <thead>
      <tr>
        <th scope="col" class="num">#</th>
        <th scope="col" class="num">Candidate</th>
        <th scope="col" class="num">Relation held</th>
        <th scope="col" class="num">Bias</th>
        <th scope="col">Distance from a coin flip</th>
      </tr>
    </thead>
    <tbody>${rows}</tbody>
  `;
}

/**
 * The screening report. Its job is to make the wrong-key randomisation
 * hypothesis visible as an assumption that was checked, rather than an
 * assumption that was made.
 */
export function renderScreening(el: HTMLElement, selected: SelectedApproximation, half: NibbleHalf): void {
  const { screen, trail } = selected;
  el.innerHTML = `
    <p>
      Matsui's search ranks approximations by the bias the piling-up lemma predicts. That ranking is a shopping list,
      not a guarantee: it says nothing about whether the <em>wrong</em> key guesses will look like noise. So each
      candidate is screened against the real cipher before the attack ships with it.
    </p>
    <p class="equation">${maskTerms(trail.startMask, 'P', 8)} &nbsp;=&nbsp; ${maskTerms(trail.endMask, 'U', 8)}</p>
    <p>
      This one was <strong>candidate #${selected.rank}</strong> in the ranking, predicted bias
      <strong>${asFraction(trail.bias, 4096)}</strong>. Screened over ${screen.trials} keys using the whole codebook, it
      named the correct nibble <strong>${screen.outrightBreaks} of ${screen.trials}</strong> times
      (${percent(screen.ceiling, 0)}), beating the best wrong candidate by ${signed(screen.meanGap)} on average.
    </p>
    ${
      selected.usable
        ? `<p>${selected.screened === 1 ? 'The top-ranked candidate passed on the first try.' : `The ${selected.screened - 1} stronger-looking ${plural(selected.screened - 1, 'candidate')} above it failed screening — same predicted bias, no ability to name the key.`}</p>`
        : `<p>
             <strong>No candidate passed.</strong> Every approximation screened leaves the correct value tied with an
             impostor, so the ${half} nibble of this cipher's final subkey cannot be pinned down this way — the attack
             shown above is the best of a bad list. This is not a bug in the demo: it is a property of an 8-bit block,
             where a wrong key guess has only 256 plaintexts to look wrong on. Switch the S-box or the target nibble and
             the picture changes.
           </p>`
    }
  `;
}
