import { enumerateApproximation, type LatTable } from '../crypto/lat.js';
import type { Sbox } from '../crypto/sbox.js';
import { bin4, esc, hexNibble, magnitude, maskTerms, maskTermsPlain, signed } from './format.js';

export interface LatSelection {
  readonly a: number;
  readonly b: number;
}

/** Mask pairs the currently displayed trail actually uses, per S-box layer. */
export interface TrailCell {
  readonly a: number;
  readonly b: number;
  readonly round: number;
}

/**
 * The 16x16 table. Each cell is a button carrying its own count, so the value
 * is readable without colour and reachable from the keyboard; the tint only
 * reinforces what the number already says.
 */
export function renderLatTable(
  table: HTMLTableElement,
  lat: LatTable,
  selected: LatSelection | null,
  onTrail: readonly TrailCell[],
): void {
  const header = [
    '<thead><tr><th scope="col"><span class="sr-only">Input mask</span>a\\b</th>',
    ...Array.from({ length: 16 }, (_, b) => `<th scope="col">${b.toString(16).toUpperCase()}</th>`),
    '</tr></thead>',
  ].join('');

  const rows = Array.from({ length: 16 }, (_, a) => {
    const cells = Array.from({ length: 16 }, (_, b) => {
      const count = lat.counts[a][b];
      const trivial = a === 0 || b === 0;
      const trailUse = onTrail.filter((c) => c.a === a && c.b === b);
      const classes = ['lat-cell'];
      if (trivial) classes.push('is-trivial');
      if (trailUse.length > 0) classes.push('is-on-trail');
      // Row 0 and column 0 are structural, not leaks: "0 = 0" holds 16/16 and
      // says nothing. Tinting them would make the emptiest statement in the
      // table look like its loudest, so they stay flat.
      const strength = Math.min(1, Math.abs(count) / 8);
      const tint =
        count === 0 || trivial
          ? ''
          : `background-color:color-mix(in oklab, var(--accent) ${Math.round(strength * 62)}%, var(--grid-zero));`;
      const pressed = selected && selected.a === a && selected.b === b ? 'true' : 'false';
      const label = [
        `input mask ${bin4(a)}, output mask ${bin4(b)}:`,
        `holds ${count + 8} of 16, bias ${signed(count / 16)}`,
        trailUse.length > 0 ? `— used by round ${trailUse.map((c) => c.round).join(' and ')} of the current trail` : '',
      ]
        .filter(Boolean)
        .join(' ');
      return `<td><button type="button" class="${classes.join(' ')}" style="${tint}" data-a="${a}" data-b="${b}" aria-pressed="${pressed}" aria-label="${esc(label)}">${count > 0 ? '+' : ''}${count}</button></td>`;
    }).join('');
    return `<tr><th scope="row">${a.toString(16).toUpperCase()}</th>${cells}</tr>`;
  }).join('');

  table.innerHTML = `${table.querySelector('caption')?.outerHTML ?? ''}${header}<tbody>${rows}</tbody>`;
}

/**
 * The evidence behind one cell: both sides of the approximation computed
 * separately for all 16 inputs and compared. The table's number is the sum of
 * the last column — nothing is taken on trust.
 */
export function renderLatDetail(el: HTMLElement, sbox: Sbox, lat: LatTable, a: number, b: number): void {
  const rows = enumerateApproximation(sbox, a, b);
  const holds = rows.filter((r) => r.holds).length;
  const count = lat.counts[a][b];
  const bias = count / 16;

  const trivial = a === 0 || b === 0;
  const verdict = trivial
    ? a === 0 && b === 0
      ? 'The empty relation: 0 = 0, true for every input. It carries no information about anything.'
      : 'One side selects no bits at all, so this is "a coin flip equals a constant". For a bijective S-box it holds exactly half the time — no leak, and none possible.'
    : count === 0
      ? 'Perfectly balanced: it holds exactly 8 times out of 16. This approximation is worthless to an attacker, which is what every cell would look like in an ideal S-box.'
      : `A leak. It holds ${holds} times out of 16 instead of 8, so an attacker who sees this relation is right ${((holds / 16) * 100).toFixed(1)}% of the time rather than 50%.`;

  el.innerHTML = `
    <h3>Approximation ${hexNibble(a)} → ${hexNibble(b)}</h3>
    <p class="equation">${maskTerms(a, 'X', 4)} &nbsp;=&nbsp; ${maskTerms(b, 'Y', 4)}</p>
    <div class="lat-evidence-wrap" role="region" aria-label="Evidence for the selected approximation" tabindex="0">
      <table class="evidence">
        <thead>
          <tr>
            <th scope="col">x</th>
            <th scope="col">S(x)</th>
            <th scope="col">left</th>
            <th scope="col">right</th>
            <th scope="col">equal?</th>
          </tr>
        </thead>
        <tbody>
          ${rows
            .map(
              (r) => `<tr class="${r.holds ? 'holds' : 'fails'}">
                <td>${bin4(r.x)}</td>
                <td>${bin4(r.sx)}</td>
                <td>${r.lhs}</td>
                <td>${r.rhs}</td>
                <td>${r.holds ? '✓ yes' : '✗ no'}</td>
              </tr>`,
            )
            .join('')}
        </tbody>
      </table>
    </div>
    <p class="tally">
      Holds <strong>${holds}/16</strong> · bias ε = ${holds}/16 − 1/2 = <strong>${bias === 0 ? '0' : `${bias < 0 ? '−' : '+'}${magnitude(bias, 16)}`}</strong>
      (${signed(bias)}) · correlation <strong>${signed(2 * bias)}</strong>
    </p>
    <p class="control-note">${esc(verdict)}</p>
    <p class="sr-only">${esc(`${maskTermsPlain(a, 'X', 4)} equals ${maskTermsPlain(b, 'Y', 4)} for ${holds} of the 16 inputs.`)}</p>
  `;
}
