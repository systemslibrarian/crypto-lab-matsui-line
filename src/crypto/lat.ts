/**
 * The Linear Approximation Table (LAT) — Matsui 1993, Table 1's idea.
 *
 * For every pair of masks (a, b) the table records how often the linear
 * approximation
 *
 *     <a, x>  XOR  <b, S(x)>  =  0
 *
 * holds over all 16 inputs x. A perfect S-box would satisfy every non-trivial
 * approximation exactly 8 times out of 16 — a coin flip, no information. Every
 * deviation from 8 is a leak, and the LAT is the complete inventory of leaks.
 *
 * Conventions used throughout this lab (Matsui's):
 *   matches      = #{ x : <a,x> = <b,S(x)> }        in 0..16
 *   biasCount    = matches - 8                       in -8..+8
 *   bias  eps    = biasCount / 16                    in -1/2..+1/2
 *   correlation  = 2 * eps                           in -1..+1
 *
 * The correlation form is what composes: correlations multiply across rounds,
 * which is the piling-up lemma written without the powers of two.
 */

import { dot, type Sbox } from './sbox.js';

export interface LatTable {
  /** biasCount[a][b] = matches - 8, in -8..+8. */
  readonly counts: readonly (readonly number[])[];
  /** Largest |biasCount| over non-trivial masks (a,b both non-zero). */
  readonly maxAbsBiasCount: number;
  /** The (a,b) pairs achieving that maximum. */
  readonly best: readonly { a: number; b: number; biasCount: number }[];
}

export function buildLat(sbox: Sbox): LatTable {
  const counts: number[][] = [];
  for (let a = 0; a < 16; a++) {
    const row = new Array<number>(16).fill(0);
    for (let b = 0; b < 16; b++) {
      let matches = 0;
      for (let x = 0; x < 16; x++) {
        if (dot(a, x) === dot(b, sbox.table[x])) matches++;
      }
      row[b] = matches - 8;
    }
    counts.push(row);
  }

  let maxAbsBiasCount = 0;
  for (let a = 1; a < 16; a++) {
    for (let b = 1; b < 16; b++) {
      maxAbsBiasCount = Math.max(maxAbsBiasCount, Math.abs(counts[a][b]));
    }
  }
  const best: { a: number; b: number; biasCount: number }[] = [];
  for (let a = 1; a < 16; a++) {
    for (let b = 1; b < 16; b++) {
      if (Math.abs(counts[a][b]) === maxAbsBiasCount) best.push({ a, b, biasCount: counts[a][b] });
    }
  }
  return { counts, maxAbsBiasCount, best };
}

/** bias = biasCount / 16. */
export function biasOf(lat: LatTable, a: number, b: number): number {
  return lat.counts[a & 0xf][b & 0xf] / 16;
}

/** correlation = 2 * bias, the quantity that multiplies across rounds. */
export function correlationOf(lat: LatTable, a: number, b: number): number {
  return lat.counts[a & 0xf][b & 0xf] / 8;
}

export interface ApproximationRow {
  readonly x: number;
  readonly sx: number;
  readonly lhs: number;
  readonly rhs: number;
  readonly holds: boolean;
}

/**
 * The full 16-row evidence behind one LAT cell: both sides of the
 * approximation computed independently and compared, for every input.
 * Nothing here is asserted — the count in the table is the sum of this column.
 */
export function enumerateApproximation(sbox: Sbox, a: number, b: number): ApproximationRow[] {
  const rows: ApproximationRow[] = [];
  for (let x = 0; x < 16; x++) {
    const sx = sbox.table[x];
    const lhs = dot(a, x);
    const rhs = dot(b, sx);
    rows.push({ x, sx, lhs, rhs, holds: lhs === rhs });
  }
  return rows;
}

/** Render a mask as the XOR of the bits it selects, e.g. "X4 ⊕ X1". */
export function maskTerms(mask: number, symbol: string, width: number): string {
  const terms: string[] = [];
  for (let i = width - 1; i >= 0; i--) {
    if ((mask >> i) & 1) terms.push(`${symbol}${i}`);
  }
  return terms.length === 0 ? '0' : terms.join(' ⊕ ');
}
