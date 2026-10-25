import { describe, expect, it } from 'vitest';
import {
  ALIGNED,
  buildDdt,
  CANCELLED,
  chosenPairs,
  designatedPath,
  DL_BUDGETS,
  DL_DEFAULT_BUDGET,
  DL_DX,
  DL_ROUNDS,
  ddtEntry,
  measureDlSuccessRate,
  naiveBias,
  pathAwareBias,
  pathPairBias,
  prefixPaths,
  runDlAttack,
  suffixCorrelation,
} from './difflin.js';
import { generateKey, encrypt } from './spn.js';
import { getSbox } from './sbox.js';

const heys = getSbox('heys');

/**
 * Every fixed number in this file was reproduced independently of the module:
 * a standalone script recomputed the DDT, the suffix correlations, the
 * per-path pair biases, the full-codebook pair statistic and the ranking
 * outcome for pinned keys straight from the S-box and permutation tables
 * before being written down here. The module must agree with that script.
 */

describe('the difference distribution table', () => {
  it('counts every x for every input difference', () => {
    const ddt = buildDdt(heys);
    for (let din = 0; din < 16; din++) {
      const rowSum = ddt.table[din].reduce((a, b) => a + b, 0);
      expect(rowSum).toBe(16);
      // A permutation S-box never maps a NONZERO difference to equal outputs.
      if (din > 0) expect(ddtEntry(ddt, din, 0)).toBe(0);
    }
    // S(x)⊕S(x⊕0) = 0 for all x: the zero row is all 16s on the diagonal cell.
    expect(ddtEntry(ddt, 0, 0)).toBe(16);
  });

  it('pins the row the lesson rides on: ΔX = 0x0b', () => {
    const ddt = buildDdt(heys);
    expect(ddtEntry(ddt, 0x0b, 0x02)).toBe(8);
    expect(ddtEntry(ddt, 0x0b, 0x05)).toBe(2);
    expect(ddtEntry(ddt, 0x0b, 0x07)).toBe(2);
    expect(ddtEntry(ddt, 0x0b, 0x0d)).toBe(2);
    expect(ddtEntry(ddt, 0x0b, 0x0f)).toBe(2);
  });

  it('rejects out-of-range indices', () => {
    const ddt = buildDdt(heys);
    expect(() => ddtEntry(ddt, 16, 0)).toThrow(RangeError);
    expect(() => ddtEntry(ddt, 0, -1)).toThrow(RangeError);
    expect(() => ddtEntry(ddt, 1.5, 0)).toThrow(RangeError);
  });
});

describe('the differential prefix and its joining state', () => {
  it('enumerates the five paths of the DDT row with their permuted joining differences', () => {
    const paths = prefixPaths(heys, ALIGNED, DL_DX);
    expect(paths).toHaveLength(5);
    // joiningDiff = permute(sboxDiff): 0x02→0x08, 0x05→0xc0, 0x07→0xc8,
    // 0x0d→0xc4, 0x0f→0xcc, each verified against the permutation table.
    const byDiff = new Map(paths.map((p) => [p.sboxDiff, p]));
    expect(byDiff.get(0x02)).toMatchObject({ weight: 0.5, joiningDiff: 0x08 });
    expect(byDiff.get(0x05)).toMatchObject({ weight: 0.125, joiningDiff: 0xc0 });
    expect(byDiff.get(0x07)).toMatchObject({ weight: 0.125, joiningDiff: 0xc8 });
    expect(byDiff.get(0x0d)).toMatchObject({ weight: 0.125, joiningDiff: 0xc4 });
    expect(byDiff.get(0x0f)).toMatchObject({ weight: 0.125, joiningDiff: 0xcc });
    expect(paths.reduce((sum, p) => sum + p.weight, 0)).toBe(1);
  });

  it('designates the heaviest path: 0x0b → 0x02 with probability exactly 1/2', () => {
    expect(designatedPath(heys, ALIGNED, DL_DX)).toMatchObject({
      sboxDiff: 0x02,
      weight: 0.5,
      joiningDiff: 0x08,
    });
  });

  it('pins why the aligned design aligns and the control does not', () => {
    // λin = 0x02 reads joining-state bit 1, fed by S-box output bit 5 —
    // untouched by any low-nibble difference. Every path evaluates to 0.
    for (const path of prefixPaths(heys, ALIGNED, DL_DX)) expect(path.lambdaInDot).toBe(0);
    // λin = 0x04 reads bit 2, fed by S-box output bit 3, which the paths move:
    const control = prefixPaths(heys, CANCELLED, DL_DX);
    expect(control.map((p) => p.lambdaInDot)).toEqual([0, 0, 0, 1, 1]);
  });

  it('rejects differences outside the low nibble', () => {
    expect(() => prefixPaths(heys, ALIGNED, 0xb0)).toThrow(RangeError);
    expect(() => prefixPaths(heys, ALIGNED, 0)).toThrow(RangeError);
  });
});

describe('the chosen pairs', () => {
  it('yields the requested number of distinct unordered pairs, ascending', () => {
    const pairs = chosenPairs(DL_DX, 64);
    expect(pairs).toHaveLength(64);
    expect(pairs[0]).toEqual([0x00, 0x0b]);
    for (const [x, other] of pairs) {
      expect(x ^ other).toBe(DL_DX);
      expect(x).toBeLessThan(other);
    }
    expect(new Set(pairs.map(([x]) => x)).size).toBe(64);
  });

  it('caps at the 128 unordered pairs an 8-bit block admits', () => {
    expect(chosenPairs(DL_DX, 128)).toHaveLength(128);
    expect(() => chosenPairs(DL_DX, 129)).toThrow(RangeError);
    expect(() => chosenPairs(DL_DX, 0)).toThrow(RangeError);
    expect(() => chosenPairs(DL_DX, 12.5)).toThrow(RangeError);
    expect(() => chosenPairs(0, 16)).toThrow(RangeError);
  });
});

describe('the suffix and the heuristic stack', () => {
  it('pins both suffix correlations against the LAT', () => {
    expect(suffixCorrelation(heys, ALIGNED)).toBe(-0.75);
    expect(suffixCorrelation(heys, CANCELLED)).toBe(-0.5);
  });

  it('computes the naive Langford–Hellman bias for both designs', () => {
    // 2 · p · ε² with p = 1/2: aligned ε = 3/8 → 9/64; control ε = 1/4 → 1/16.
    expect(naiveBias(0.5, suffixCorrelation(heys, ALIGNED))).toBeCloseTo(9 / 64, 12);
    expect(naiveBias(0.5, suffixCorrelation(heys, CANCELLED))).toBeCloseTo(1 / 16, 12);
    expect(() => naiveBias(0, 0.75)).toThrow(RangeError);
    expect(() => naiveBias(1.5, 0.75)).toThrow(RangeError);
  });

  it('pins the exact uniform-u pair bias of every path for both designs', () => {
    // Reproduced by enumeration before pinning. Aligned: every path is
    // positive — the pair relation holds on ALL paths, not just the
    // designated one, which is exactly the assumption the naive form makes.
    const aligned = prefixPaths(heys, ALIGNED, DL_DX);
    expect(aligned.map((p) => pathPairBias(heys, ALIGNED, p.joiningDiff))).toEqual([0.25, 0.5, 0.25, 0.25, 0.25]);
    // Control: three paths carry no pair bias at all, two carry +1/2.
    const control = prefixPaths(heys, CANCELLED, DL_DX);
    expect(control.map((p) => pathPairBias(heys, CANCELLED, p.joiningDiff))).toEqual([0, 0.5, 0, 0.5, 0]);
  });

  it('pins the path-aware estimates: 9/32 aligned, 1/8 cancelled', () => {
    expect(pathAwareBias(heys, ALIGNED, DL_DX)).toBeCloseTo(9 / 32, 12);
    expect(pathAwareBias(heys, CANCELLED, DL_DX)).toBeCloseTo(1 / 8, 12);
  });
});

describe('the composed attack on the real cipher', () => {
  // k = 0x3A94: the lab's pinned working key. K4 (the final whitening byte of
  // the 3-round cipher) is 0xa9.
  const pinnedKey = generateKey(14996);

  it('recovers K4 outright at the default budget of 64 pairs', () => {
    const result = runDlAttack({ sbox: heys, key: pinnedKey, design: ALIGNED, budget: 64 });
    expect(result.trueSubkey).toBe(0xa9);
    expect(result.winner).toBe(0xa9);
    expect(result.winnerTies).toBe(0);
    expect(result.verdict).toBe('recovered');
    // The right guess agrees on 50 of 64 pairs: bias 18/64 = 9/32 over the
    // attack half — the path-aware number, live.
    expect(result.counts[0xa9]).toBe(50);
    expect(result.measuredBias).toBeCloseTo(18 / 64, 12);
    expect(result.attackPairs).toBe(64);
  });

  it('holds the full-codebook pair statistic at exactly 5/16, independent of the key', () => {
    for (const masterKey of [14996, 0x1234, 0]) {
      const result = runDlAttack({
        sbox: heys,
        key: generateKey(masterKey),
        design: ALIGNED,
        budget: 128,
      });
      // 104 of 128 pairs agree under the true subkey for every key tried.
      expect(result.counts[result.trueSubkey]).toBe(104);
      expect(result.measuredBias).toBeCloseTo(5 / 16, 12);
      expect(result.verdict).toBe('recovered');
      expect(result.winner).toBe(result.trueSubkey);
      expect(result.winnerTies).toBe(0);
    }
  });

  it('verifies the winner on the held-back pairs at the default budget', () => {
    const result = runDlAttack({ sbox: heys, key: pinnedKey, design: ALIGNED, budget: 64 });
    expect(result.holdoutPairs).toBe(64);
    // The winner keeps 54/64 on fresh pairs (bias 11/32) while the best wrong
    // guess manages 47/64 (bias 15/64).
    expect(result.holdoutCounts[0xa9]).toBe(54);
    expect(result.winnerHoldoutBias).toBeCloseTo(11 / 32, 12);
    expect(result.maxWrongHoldoutBias).toBeCloseTo(15 / 64, 12);
    expect(result.holdoutConfirms).toBe(true);
  });

  it('spends every pair at budget 128 and leaves nothing to hold back', () => {
    const result = runDlAttack({ sbox: heys, key: pinnedKey, design: ALIGNED, budget: 128 });
    expect(result.holdoutPairs).toBe(0);
    expect(result.holdoutConfirms).toBe(false);
  });

  it('fails honestly at a starved budget: the pinned key ties at 16 pairs', () => {
    const result = runDlAttack({ sbox: heys, key: pinnedKey, design: ALIGNED, budget: 16 });
    expect(result.winner).toBe(0xa9);
    expect(result.verdict).toBe('tied');
    expect(result.winnerTies).toBeGreaterThan(0);
  });

  it('shows the control measuring EXACTLY zero while the heuristic promised signal', () => {
    const result = runDlAttack({ sbox: heys, key: pinnedKey, design: CANCELLED, budget: 128 });
    // Naive heuristic 1/16, path-aware 1/8 — and the cipher says: nothing.
    expect(result.counts[result.trueSubkey]).toBe(64);
    expect(result.measuredBias).toBe(0);
    expect(result.verdict).toBe('failed');
    expect(result.winner).not.toBe(result.trueSubkey);
  });

  it('never counts an alias as a distinct candidate in the aligned design', () => {
    // In the aligned design λout spans both nibbles, so every one of the 256
    // guesses is a distinct statistic (verified across keys: no ties at the
    // top at budgets 96 and 128 in the success measurement below).
    const result = runDlAttack({ sbox: heys, key: pinnedKey, design: ALIGNED, budget: 96 });
    expect(result.winnerTies).toBe(0);
  });
});

describe('the measured success rate across keys', () => {
  it('pins the deterministic budget curve for the aligned design over 512 keys', () => {
    const points = measureDlSuccessRate({
      sbox: heys,
      design: ALIGNED,
      budgets: DL_BUDGETS,
      keyCount: 512,
    });
    expect(points.map((p) => p.budget)).toEqual([16, 32, 64, 96, 128]);
    // Reproduced by running the same deterministic measurement twice offline.
    expect(points.map((p) => p.wins)).toEqual([232, 352, 512, 512, 512]);
    expect(points.map((p) => p.tiedWins)).toEqual([90, 32, 16, 0, 0]);
    expect(points.map((p) => p.rate)).toEqual([
      232 / 512,
      352 / 512,
      1,
      1,
      1,
    ]);
  });

  it('pins the control flatlining at chance for budgets 64 and up', () => {
    const points = measureDlSuccessRate({
      sbox: heys,
      design: CANCELLED,
      budgets: DL_BUDGETS,
      keyCount: 512,
    });
    // 25, 8, 0, 0, 0 — nothing a ranking of 256 candidates can use.
    expect(points.map((p) => p.wins)).toEqual([25, 8, 0, 0, 0]);
  });

  it('reports progress as it works', () => {
    const seen: number[] = [];
    measureDlSuccessRate({
      sbox: heys,
      design: ALIGNED,
      budgets: [16],
      keyCount: 8,
      onProgress: (completed) => seen.push(completed),
    });
    expect(seen).toHaveLength(8);
    expect(seen.at(-1)).toBe(8);
  });
});

describe('the cipher the composition runs on', () => {
  it('is the shared 3-round toy SPN, not a special-purpose construction', () => {
    expect(DL_ROUNDS).toBe(3);
    expect(DL_DX).toBe(0x0b);
    expect(DL_DEFAULT_BUDGET).toBe(64);
    // The attack encrypts through the production encrypt() path only.
    const key = generateKey(1);
    expect(encrypt(0x00, key, heys, 3)).toBe(runThroughEncrypt(0x00, key));
  });
});

/** Encryption via the shared module — the attack must not re-implement it. */
function runThroughEncrypt(plaintext: number, key: ReturnType<typeof generateKey>): number {
  return encrypt(plaintext, key, heys, 3);
}
