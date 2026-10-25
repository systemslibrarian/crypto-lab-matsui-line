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
import { dot, getSbox } from './sbox.js';

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

  it('computes the Biham–Dunkelman–Keller p-weighted bias for both designs', () => {
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
    const alignedRhs = designatedPath(heys, ALIGNED, DL_DX).lambdaInDot;
    expect(aligned.map((p) => pathPairBias(heys, ALIGNED, p.joiningDiff, alignedRhs))).toEqual([0.25, 0.5, 0.25, 0.25, 0.25]);
    // The attack fixes one RHS. In the control, the 0x05 and 0x0d paths
    // carry equal and opposite bias rather than each choosing its own RHS.
    const control = prefixPaths(heys, CANCELLED, DL_DX);
    const controlRhs = designatedPath(heys, CANCELLED, DL_DX).lambdaInDot;
    expect(control.map((p) => pathPairBias(heys, CANCELLED, p.joiningDiff, controlRhs))).toEqual([0, 0.5, 0, -0.5, 0]);
    expect(() => pathPairBias(heys, CANCELLED, control[0].joiningDiff, 2)).toThrow(RangeError);
  });

  it('pins the path-aware estimates: 9/32 aligned, zero after signed control paths cancel', () => {
    expect(pathAwareBias(heys, ALIGNED, DL_DX)).toBeCloseTo(9 / 32, 12);
    expect(pathAwareBias(heys, CANCELLED, DL_DX)).toBe(0);
  });
});

describe('the composed attack on the real cipher', () => {
  // k = 0x3A94: the lab's pinned working key. K4 (the final whitening byte of
  // the 3-round cipher) is 0xa9.
  const pinnedKey = generateKey(14996);

  it('recovers K4 outright at a 64-pair budget', () => {
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

  it('shows the full-codebook pair statistic is key-dependent, not a fixed 5/16', () => {
    for (const [masterKey, agreements, bias] of [
      [14996, 104, 5 / 16],
      [0x4000, 96, 1 / 4],
    ] as const) {
      const result = runDlAttack({
        sbox: heys,
        key: generateKey(masterKey),
        design: ALIGNED,
        budget: 128,
      });
      expect(result.counts[result.trueTarget]).toBe(agreements);
      expect(result.measuredBias).toBeCloseTo(bias, 12);
      expect(result.verdict).toBe('recovered');
      expect(result.winner).toBe(result.trueSubkey);
      expect(result.winnerTies).toBe(0);
    }
  });

  it('exhaustively bounds the full-codebook biases across all 65,536 master keys', { timeout: 30_000 }, () => {
    const pairs = chosenPairs(DL_DX, 128);
    const alignedRhs = designatedPath(heys, ALIGNED, DL_DX).lambdaInDot;
    const controlRhs = designatedPath(heys, CANCELLED, DL_DX).lambdaInDot;
    const alignedHistogram = new Map<number, number>();
    let nonzeroControls = 0;

    // Independent true-key count: this deliberately does not call
    // runDlAttack(), its ranking, or its measuredBias field.
    for (let masterKey = 0; masterKey <= 0xffff; masterKey++) {
      const key = generateKey(masterKey);
      const trueSubkey = key.subkeys[DL_ROUNDS];
      let alignedAgreements = 0;
      let controlAgreements = 0;
      for (const [x, other] of pairs) {
        const c1 = encrypt(x, key, heys, DL_ROUNDS);
        const c2 = encrypt(other, key, heys, DL_ROUNDS);
        const v1 = (heys.inverse[(c1 ^ trueSubkey) >> 4] << 4) | heys.inverse[(c1 ^ trueSubkey) & 0xf];
        const v2 = (heys.inverse[(c2 ^ trueSubkey) >> 4] << 4) | heys.inverse[(c2 ^ trueSubkey) & 0xf];
        if ((dot(ALIGNED.lambdaOut, v1) ^ dot(ALIGNED.lambdaOut, v2) ^ alignedRhs) === 0) alignedAgreements++;
        if ((dot(CANCELLED.lambdaOut, v1) ^ dot(CANCELLED.lambdaOut, v2) ^ controlRhs) === 0) controlAgreements++;
      }
      alignedHistogram.set(alignedAgreements, (alignedHistogram.get(alignedAgreements) ?? 0) + 1);
      if (controlAgreements !== 64) nonzeroControls++;
    }

    expect([...alignedHistogram.entries()].sort((a, b) => a[0] - b[0])).toEqual([
      [96, 32_768],
      [104, 32_768],
    ]);
    expect(nonzeroControls).toBe(0);
  });

  it('verifies the winner on the held-back pairs at the default budget', () => {
    const result = runDlAttack({ sbox: heys, key: pinnedKey, design: ALIGNED, budget: 64 });
    expect(result.holdoutPairs).toBe(64);
    // The winner keeps 54/64 on fresh pairs (bias 11/32) while the best wrong
    // rival hypothesis has 47/64 (bias 15/64).
    expect(result.holdoutCounts[0xa9]).toBe(54);
    expect(result.winnerHoldoutBias).toBeCloseTo(11 / 32, 12);
    expect(result.maxOtherHoldoutBias).toBeCloseTo(15 / 64, 12);
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

  it('counts the true key in a top tie even when numeric tie-breaking lists another guess first', () => {
    const result = runDlAttack({ sbox: heys, key: generateKey(5418), design: ALIGNED, budget: 16 });
    expect(result.winner).toBe(0x42);
    expect(result.trueTarget).toBe(0x52);
    expect(result.winnerTies).toBe(2);
    expect(result.verdict).toBe('tied');
  });

  it('shows the control measuring EXACTLY zero while the heuristic promised signal', () => {
    const result = runDlAttack({ sbox: heys, key: pinnedKey, design: CANCELLED, budget: 128 });
    // Naive heuristic 1/16, corrected signed path sum zero — and the real
    // cipher agrees. The 0xc0 mask sees only the high key nibble, so only 16
    // canonical hypotheses are ranked and no low-nibble recovery is claimed.
    expect(result.candidates).toEqual(Array.from({ length: 16 }, (_, guess) => guess << 4));
    expect(result.targetMask).toBe(0xf0);
    expect(result.trueTarget).toBe(0xa0);
    expect(result.counts[result.trueTarget]).toBe(64);
    expect(result.measuredBias).toBe(0);
    expect(result.verdict).toBe('failed');
    expect(result.winner).not.toBe(result.trueSubkey);

    // A partial budget is only a sample of that zero-bias population. It must
    // not be conflated with the exact path sum or full-codebook measurement.
    const finite = runDlAttack({ sbox: heys, key: pinnedKey, design: CANCELLED, budget: 32 });
    expect(finite.measuredBias).toBe(-1 / 8);
  });

  it('never counts an alias as a distinct candidate in the aligned design', () => {
    // In the aligned design λout spans both nibbles, so every one of the 256
    // guesses is a distinct statistic (verified across keys: no ties at the
    // top at budgets 96 and 128 in the success measurement below).
    const result = runDlAttack({ sbox: heys, key: pinnedKey, design: ALIGNED, budget: 96 });
    expect(result.attackPairs).toBe(96);
    expect(result.holdoutPairs).toBe(32);
    expect(2 * (result.attackPairs + result.holdoutPairs)).toBe(256);
    expect(result.winnerTies).toBe(0);
  });
});

describe('the measured success rate across keys', () => {
  it('pins the deterministic budget curve for the aligned design over 512 stride-walked keys', { timeout: 30_000 }, () => {
    const points = measureDlSuccessRate({
      sbox: heys,
      design: ALIGNED,
      budgets: DL_BUDGETS,
      keyCount: 512,
    });
    expect(points.map((p) => p.budget)).toEqual([16, 32, 64, 96, 128]);
    // Reproduced by running the same deterministic measurement offline, twice.
    // The keys are 0, 129, 258, … — an odd stride that disperses this bounded
    // deterministic sample instead of staying inside a consecutive
    // key-schedule pocket. It is reproducible, not a random population claim.
    expect(points.map((p) => p.wins)).toEqual([160, 342, 462, 511, 512]);
    expect(points.map((p) => p.tiedWins)).toEqual([67, 92, 52, 0, 0]);
    expect(points.map((p) => p.rate)).toEqual([
      160 / 512,
      342 / 512,
      462 / 512,
      511 / 512,
      1,
    ]);
  });

  it('pins the signal-free control over the 16 high-nibble hypotheses', { timeout: 30_000 }, () => {
    const points = measureDlSuccessRate({
      sbox: heys,
      design: CANCELLED,
      budgets: DL_BUDGETS,
      keyCount: 512,
    });
    // At small budgets the true nibble can sit in a chance tie. Once the full
    // zero-bias population is exposed, it never wins the noise ranking.
    expect(points.map((p) => p.wins)).toEqual([100, 70, 10, 0, 0]);
    expect(points.map((p) => p.tiedWins)).toEqual([96, 68, 10, 0, 0]);
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
    expect(DL_DEFAULT_BUDGET).toBe(96);
    // The attack encrypts through the production encrypt() path only.
    const key = generateKey(1);
    expect(encrypt(0x00, key, heys, 3)).toBe(runThroughEncrypt(0x00, key));
  });
});

/** Encryption via the shared module — the attack must not re-implement it. */
function runThroughEncrypt(plaintext: number, key: ReturnType<typeof generateKey>): number {
  return encrypt(plaintext, key, heys, 3);
}
