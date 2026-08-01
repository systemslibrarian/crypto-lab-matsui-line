import { describe, expect, it } from 'vitest';
import { buildLat } from './lat.js';
import { permute, permuteMask, permuteMaskInverse } from './permutation.js';
import { dot, getSbox, substitute } from './sbox.js';
import { generateKey } from './spn.js';
import {
  bestTrail,
  biasAcrossKeys,
  buildTrail,
  exactBias,
  maskHalf,
  pilingUpBias,
  rankApproximations,
  roundCorrelation,
  sboxLayerCorrelation,
  trailBetween,
  verifyStep,
} from './trail.js';

const heys = getSbox('heys');
const present = getSbox('present');

describe('piling-up lemma', () => {
  /**
   * Heys' tutorial builds a 3-round approximation from four active S-boxes with
   * biases +1/4, -1/4, -1/4, -1/4 and reports a total bias of -1/32. This is the
   * lemma's published worked example.
   */
  it('reproduces the total bias of the worked example in the Heys tutorial', () => {
    expect(pilingUpBias([1 / 4, -1 / 4, -1 / 4, -1 / 4])).toBeCloseTo(-1 / 32, 12);
  });

  it('agrees with multiplying correlations', () => {
    const biases = [0.25, -0.125, 0.375, -0.0625];
    const viaCorrelations = biases.reduce((acc, e) => acc * 2 * e, 1) / 2;
    expect(pilingUpBias(biases)).toBeCloseTo(viaCorrelations, 12);
  });

  it('collapses to zero as soon as one round is unbiased', () => {
    expect(pilingUpBias([0.25, 0, 0.25])).toBe(0);
  });

  it('returns the single bias unchanged for one round', () => {
    expect(pilingUpBias([0.3])).toBeCloseTo(0.3, 12);
  });
});

describe('mask propagation', () => {
  it('a mask crosses the bit permutation exactly as a value does', () => {
    for (let gamma = 0; gamma < 256; gamma++) {
      for (let v = 0; v < 256; v++) {
        expect(dot(gamma, v)).toBe(dot(permuteMask(gamma), permute(v)));
      }
    }
  });

  it('permuteMask and permuteMaskInverse cancel', () => {
    for (let m = 0; m < 256; m++) expect(permuteMaskInverse(permuteMask(m))).toBe(m);
  });
});

describe('round correlation', () => {
  for (const sbox of [heys, present]) {
    it(`matches a brute-force count over the real round function — ${sbox.name}`, () => {
      const lat = buildLat(sbox);
      // The round is S-box layer then permutation; count how often the parity
      // relation holds over all 256 inputs and compare with the factorised
      // per-nibble product the trail search relies on.
      for (let alpha = 0; alpha < 256; alpha += 7) {
        for (let beta = 0; beta < 256; beta += 5) {
          let matches = 0;
          for (let x = 0; x < 256; x++) {
            if (dot(alpha, x) === dot(beta, permute(substitute(x, sbox)))) matches++;
          }
          const measured = 2 * (matches / 256) - 1;
          expect(roundCorrelation(lat, alpha, beta)).toBeCloseTo(measured, 12);
        }
      }
    });
  }

  it('factorises into the two nibble correlations', () => {
    const lat = buildLat(heys);
    for (let alpha = 0; alpha < 256; alpha += 11) {
      for (let gamma = 0; gamma < 256; gamma += 13) {
        const expected =
          (lat.counts[(alpha >> 4) & 0xf][(gamma >> 4) & 0xf] / 8) * (lat.counts[alpha & 0xf][gamma & 0xf] / 8);
        expect(sboxLayerCorrelation(lat, alpha, gamma)).toBeCloseTo(expected, 12);
      }
    }
  });
});

describe('trail search', () => {
  it('finds a 2-round trail with the strongest bias the S-box allows', () => {
    // Two active S-boxes at 1/4 each: 2^1 * (1/4)^2 = 1/8, and nothing beats it.
    const trail = bestTrail(heys, 2, { endHalf: 'high' });
    expect(trail).not.toBeNull();
    expect(Math.abs(trail!.bias)).toBeCloseTo(1 / 8, 12);
    expect(trail!.steps).toHaveLength(2);
    expect(bestTrail(heys, 2, { endHalf: 'high' })).toEqual(trail); // deterministic
  });

  it('loses bias with every extra round, exactly as the lemma says', () => {
    let previous = Number.POSITIVE_INFINITY;
    for (const rounds of [1, 2, 3]) {
      const trail = bestTrail(heys, rounds, { endHalf: 'high' })!;
      expect(Math.abs(trail.bias)).toBeLessThan(previous);
      previous = Math.abs(trail.bias);
    }
  });

  it('respects the end-mask constraints it is given', () => {
    for (const sbox of [heys, present]) {
      for (const rounds of [1, 2, 3]) {
        const low = bestTrail(sbox, rounds, { endHalf: 'low' });
        expect(low!.endMask & 0xf0).toBe(0);
        expect(maskHalf(low!.endMask)).toBe('low');
        const high = bestTrail(sbox, rounds, { endHalf: 'high' });
        expect(high!.endMask & 0x0f).toBe(0);
        const pinned = bestTrail(sbox, rounds, { startMask: 0b0000_1001, endMask: 0b1100_0000 });
        if (pinned) {
          expect(pinned.startMask).toBe(0b0000_1001);
          expect(pinned.endMask).toBe(0b1100_0000);
        }
      }
    }
  });

  it('reports a correlation equal to the product of its steps', () => {
    for (const sbox of [heys, present]) {
      for (const rounds of [1, 2, 3]) {
        for (const half of ['low', 'high'] as const) {
          const trail = bestTrail(sbox, rounds, { endHalf: half })!;
          const product = trail.steps.reduce((acc, s) => acc * s.correlation, 1);
          expect(trail.correlation).toBeCloseTo(product, 12);
          expect(trail.bias).toBeCloseTo(trail.correlation / 2, 12);
          expect(trail.steps).toHaveLength(rounds);
        }
      }
    }
  });

  it('links its steps into an unbroken chain of masks', () => {
    const trail = bestTrail(present, 3, { endHalf: 'low' })!;
    expect(trail.steps[0].inMask).toBe(trail.startMask);
    expect(trail.steps[trail.steps.length - 1].outMask).toBe(trail.endMask);
    for (const step of trail.steps) {
      expect(step.outMask).toBe(permuteMask(step.sboxOutMask));
      expect(step.correlation).toBeCloseTo(
        step.nibbles.reduce((acc, n) => acc * n.correlation, 1),
        12,
      );
    }
    for (let i = 1; i < trail.steps.length; i++) {
      expect(trail.steps[i].inMask).toBe(trail.steps[i - 1].outMask);
    }
  });

  it('each step survives a brute-force check against the real S-box layer', () => {
    for (const sbox of [heys, present]) {
      const trail = bestTrail(sbox, 3, { endHalf: 'high' })!;
      for (const step of trail.steps) {
        const measured = verifyStep(sbox, step.inMask, step.sboxOutMask);
        expect(step.bias).toBeCloseTo(measured.bias, 12);
      }
    }
  });

  it('is genuinely optimal — no chain beats it (checked exhaustively for 2 rounds)', () => {
    const lat = buildLat(heys);
    const trail = bestTrail(heys, 2, { endHalf: 'high' })!;
    let bestSeen = 0;
    for (let a = 1; a < 256; a++) {
      for (let mid = 1; mid < 256; mid++) {
        const first = roundCorrelation(lat, a, mid);
        if (first === 0) continue;
        for (let end = 1; end < 256; end++) {
          if (end & 0x0f) continue; // high-nibble end masks only
          const total = Math.abs(first * roundCorrelation(lat, mid, end));
          if (total > bestSeen) bestSeen = total;
        }
      }
    }
    expect(Math.abs(trail.correlation)).toBeCloseTo(bestSeen, 12);
  });

  it('rebuilds an equivalent trail from a bare chain of masks', () => {
    const lat = buildLat(heys);
    const trail = bestTrail(heys, 2, { endHalf: 'high' })!;
    const chain = [trail.startMask, ...trail.steps.map((s) => s.outMask)];
    expect(buildTrail(lat, chain).correlation).toBeCloseTo(trail.correlation, 12);
  });

  it('rejects a zero-round search', () => {
    expect(() => bestTrail(heys, 0)).toThrow(RangeError);
  });
});

describe('exact bias vs the piling-up prediction', () => {
  const shortTrail = bestTrail(heys, 2, { endHalf: 'high' })!;
  const longTrail = bestTrail(heys, 3, { endHalf: 'high' })!;
  const SPREAD_KEYS = [0x0000, 0x3a94, 0x1234, 0xbeef, 0xace1, 0xffff];

  it('measures the true bias over the whole 256-plaintext codebook', () => {
    for (const masterKey of SPREAD_KEYS) {
      const bias = exactBias(heys, generateKey(masterKey), 3, shortTrail.startMask, shortTrail.endMask);
      // A bias is a fraction of 256 plaintexts, so it is a multiple of 1/256.
      expect(Number.isInteger(bias * 256)).toBe(true);
      expect(Math.abs(bias)).toBeLessThanOrEqual(0.5);
    }
  });

  it('is EXACT over two rounds, where a single trail dominates the hull', () => {
    // Every key gives |bias| = 1/8 on the nose. The round keys move the sign
    // around and nothing else — which is what the lemma promises when there is
    // only one trail to speak of.
    const biases = biasAcrossKeys(heys, 3, shortTrail.startMask, shortTrail.endMask, SPREAD_KEYS);
    for (const bias of biases) expect(Math.abs(bias)).toBeCloseTo(Math.abs(shortTrail.bias), 12);
    expect(new Set(biases.map((b) => Math.sign(b))).size).toBeGreaterThan(1);
  });

  it('is only an ESTIMATE over three rounds, where the hull has several trails', () => {
    // Now the prediction and the truth part company, and the truth depends on
    // the key: this is the linear hull effect. The demo shows it rather than
    // quietly reporting the lemma's number as if it were measured.
    const biases = biasAcrossKeys(heys, 4, longTrail.startMask, longTrail.endMask, SPREAD_KEYS);
    const magnitudes = new Set(biases.map((b) => Math.abs(b).toFixed(6)));
    expect(magnitudes.size).toBeGreaterThan(1);
    const differsFromPrediction = biases.some(
      (b) => Math.abs(Math.abs(b) - Math.abs(longTrail.bias)) > 1e-9,
    );
    expect(differsFromPrediction).toBe(true);
    // Still the right order of magnitude — the lemma is useful, not exact.
    for (const b of biases) expect(Math.abs(b)).toBeGreaterThan(0.01);
  });

  it('vanishes for an approximation with no trail through the S-boxes', () => {
    // Mask 0 on the output side reads no bits: the relation degenerates and can
    // carry no key information.
    expect(exactBias(heys, generateKey(0x3a94), 3, 0, 0)).toBeCloseTo(0.5, 12);
  });
});

describe('approximation ranking', () => {
  it('ranks by predicted strength, strongest first, deterministically', () => {
    const ranked = rankApproximations(heys, 2, { endHalf: 'high', limit: 40 });
    expect(ranked.length).toBe(40);
    for (let i = 1; i < ranked.length; i++) {
      expect(ranked[i - 1].absCorrelation).toBeGreaterThanOrEqual(ranked[i].absCorrelation);
    }
    expect(rankApproximations(heys, 2, { endHalf: 'high', limit: 40 })).toEqual(ranked);
    for (const candidate of ranked) {
      expect(candidate.endMask & 0x0f).toBe(0);
      expect(candidate.absBias).toBeCloseTo(candidate.absCorrelation / 2, 12);
    }
  });

  it('agrees with the trail it reconstructs', () => {
    for (const sbox of [heys, present]) {
      for (const rounds of [1, 2, 3]) {
        for (const candidate of rankApproximations(sbox, rounds, { endHalf: 'high', limit: 5 })) {
          const trail = trailBetween(sbox, rounds, candidate.startMask, candidate.endMask)!;
          expect(Math.abs(trail.correlation)).toBeCloseTo(candidate.absCorrelation, 12);
          expect(trail.startMask).toBe(candidate.startMask);
          expect(trail.endMask).toBe(candidate.endMask);
        }
      }
    }
  });

  it('returns null for a mask pair no trail can join', () => {
    // A one-round trail cannot move a mask across the S-box layer arbitrarily:
    // the LAT has genuine zeros, and the search must report them as zeros.
    const lat = buildLat(heys);
    let impossible: [number, number] | null = null;
    for (let a = 1; a < 256 && !impossible; a++) {
      for (let b = 1; b < 256; b++) {
        if (roundCorrelation(lat, a, b) === 0) {
          impossible = [a, b];
          break;
        }
      }
    }
    expect(impossible).not.toBeNull();
    expect(trailBetween(heys, 1, impossible![0], impossible![1])).toBeNull();
  });
});
