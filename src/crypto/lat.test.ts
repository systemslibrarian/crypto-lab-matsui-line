import { describe, expect, it } from 'vitest';
import { biasOf, buildLat, correlationOf, enumerateApproximation, maskTerms } from './lat.js';
import { dot, getSbox } from './sbox.js';

const heys = getSbox('heys');
const present = getSbox('present');

describe('LAT known-answer tests', () => {
  /**
   * Howard Heys, "A Tutorial on Linear and Differential Cryptanalysis",
   * Section 3.2. Both approximations below are quoted there for this exact
   * S-box, in his 1-based notation where X1 is the most significant bit:
   *   X1 ⊕ X3 ⊕ X4 = Y2       holds 12/16
   *   X2           = Y2 ⊕ Y4  holds  4/16
   */
  it('reproduces the two approximations published in the Heys tutorial', () => {
    const lat = buildLat(heys);
    // X1,X3,X4 -> bits 3,1,0 = 0b1011; Y2 -> bit 2 = 0b0100.
    expect(lat.counts[0b1011][0b0100] + 8).toBe(12);
    expect(biasOf(lat, 0b1011, 0b0100)).toBeCloseTo(0.25, 12);
    // X2 -> bit 2 = 0b0100; Y2,Y4 -> bits 2,0 = 0b0101.
    expect(lat.counts[0b0100][0b0101] + 8).toBe(4);
    expect(biasOf(lat, 0b0100, 0b0101)).toBeCloseTo(-0.25, 12);
  });

  it('reproduces the published maxima of both S-boxes', () => {
    // Heys' toy S-box leaks 6/16; the PRESENT S-box was selected by Bogdanov
    // et al. (CHES 2007) so that no linear approximation exceeds 4/16.
    expect(buildLat(heys).maxAbsBiasCount).toBe(6);
    expect(buildLat(present).maxAbsBiasCount).toBe(4);
  });
});

describe('LAT structural invariants', () => {
  for (const sbox of [heys, present]) {
    it(`holds for the ${sbox.name} S-box`, () => {
      const lat = buildLat(sbox);

      // The trivial approximation 0 = 0 always holds: 16/16 matches.
      expect(lat.counts[0][0]).toBe(8);

      // A non-zero mask on only one side is a coin flip for a bijective S-box.
      for (let m = 1; m < 16; m++) {
        expect(lat.counts[0][m]).toBe(0);
        expect(lat.counts[m][0]).toBe(0);
      }

      // Parseval: correlations along any row or column are unit-norm, so the
      // squared bias counts sum to 8^2. A leak somewhere is a debt elsewhere.
      for (let a = 0; a < 16; a++) {
        expect(lat.counts[a].reduce((s, v) => s + v * v, 0)).toBe(64);
        expect(lat.counts.reduce((s, row) => s + row[a] * row[a], 0)).toBe(64);
      }

      // Parity: an odd bias count would mean an odd number of the 16 inputs
      // split unevenly, which cannot happen.
      for (let a = 0; a < 16; a++) {
        for (let b = 0; b < 16; b++) expect(Math.abs(lat.counts[a][b] % 2)).toBe(0);
      }

      // correlation = 2 * bias, everywhere.
      for (let a = 0; a < 16; a++) {
        for (let b = 0; b < 16; b++) {
          expect(correlationOf(lat, a, b)).toBeCloseTo(2 * biasOf(lat, a, b), 12);
        }
      }
    });
  }
});

describe('enumerateApproximation', () => {
  it('counts, rather than asserts, every LAT entry', () => {
    for (const sbox of [heys, present]) {
      const lat = buildLat(sbox);
      for (let a = 0; a < 16; a++) {
        for (let b = 0; b < 16; b++) {
          const rows = enumerateApproximation(sbox, a, b);
          expect(rows).toHaveLength(16);
          expect(rows.filter((r) => r.holds).length - 8).toBe(lat.counts[a][b]);
          for (const row of rows) {
            expect(row.sx).toBe(sbox.table[row.x]);
            expect(row.lhs).toBe(dot(a, row.x));
            expect(row.rhs).toBe(dot(b, row.sx));
            expect(row.holds).toBe(row.lhs === row.rhs);
          }
        }
      }
    }
  });
});

describe('maskTerms', () => {
  it('renders a mask as the XOR of the bits it selects, high bit first', () => {
    expect(maskTerms(0b1011, 'X', 4)).toBe('X3 ⊕ X1 ⊕ X0');
    expect(maskTerms(0b0100, 'Y', 4)).toBe('Y2');
    expect(maskTerms(0, 'X', 4)).toBe('0');
    expect(maskTerms(0b1000_0001, 'P', 8)).toBe('P7 ⊕ P0');
  });
});
