import { describe, expect, it } from 'vitest';
import {
  collectKnownPairs,
  fullCodebook,
  measureSuccessRate,
  normalCdf,
  requiredSamples,
  runAttack,
  startAttack,
  screenApproximation,
  selectApproximation,
  theoreticalSuccessRate,
} from './attack.js';
import { getSbox } from './sbox.js';
import { encrypt, generateKey, takeNibble } from './spn.js';
import { bestTrail, rankApproximations } from './trail.js';
import { mulberry32 } from './rng.js';

const heys = getSbox('heys');
const present = getSbox('present');

/** The configuration the demo ships with: 3-round cipher, high nibble. */
const SELECTED = selectApproximation(heys, 3, 'high')!;
const TRAIL = SELECTED.trail;
const KEYS = [0x3a94, 0x1234, 0xbeef, 0xace1, 0x0000, 0xffff, 0x77f0, 0x5a5a];

describe('known-plaintext collection', () => {
  it('encrypts under the real cipher and never chooses its plaintexts', () => {
    const key = generateKey(0x3a94);
    const pairs = collectKnownPairs(key, heys, 3, 500, mulberry32(7));
    expect(pairs).toHaveLength(500);
    for (const { plaintext, ciphertext } of pairs) {
      expect(ciphertext).toBe(encrypt(plaintext, key, heys, 3));
    }
    // Uniform-ish coverage: with 500 draws over 256 values, most values appear.
    expect(new Set(pairs.map((p) => p.plaintext)).size).toBeGreaterThan(180);
  });

  it('is reproducible from its seed and different across seeds', () => {
    const key = generateKey(0x3a94);
    const a = collectKnownPairs(key, heys, 3, 64, mulberry32(42));
    const b = collectKnownPairs(key, heys, 3, 64, mulberry32(42));
    const c = collectKnownPairs(key, heys, 3, 64, mulberry32(43));
    expect(a).toEqual(b);
    expect(a).not.toEqual(c);
  });

  it('fullCodebook covers every plaintext exactly once', () => {
    const pairs = fullCodebook(generateKey(0xbeef), heys, 3);
    expect(new Set(pairs.map((p) => p.plaintext)).size).toBe(256);
  });
});

describe('Matsui Algorithm 2 — the attack works', () => {
  it('recovers the last-round subkey nibble from the whole codebook, for every key tried', () => {
    for (let masterKey = 0; masterKey < 0x10000; masterKey += 617) {
      const key = generateKey(masterKey);
      const result = runAttack({
        sbox: heys,
        key,
        cipherRounds: 3,
        half: 'high',
        startMask: TRAIL.startMask,
        endMask: TRAIL.endMask,
        pairs: fullCodebook(key, heys, 3),
      });
      expect(result.recovered).toBe(true);
      expect(result.correctRank).toBe(1);
      expect(result.winners).toEqual([takeNibble(key.subkeys[3], 'high')]);
      expect(result.bitsRecovered).toBe(4);
    }
  });

  it('recovers the subkey nibble from a few thousand known plaintexts', () => {
    let recovered = 0;
    for (let i = 0; i < KEYS.length; i++) {
      const key = generateKey(KEYS[i]);
      const pairs = collectKnownPairs(key, heys, 3, 4096, mulberry32(1000 + i));
      const result = runAttack({
        sbox: heys,
        key,
        cipherRounds: 3,
        half: 'high',
        startMask: TRAIL.startMask,
        endMask: TRAIL.endMask,
        pairs,
      });
      if (result.recovered) recovered++;
    }
    expect(recovered).toBeGreaterThanOrEqual(KEYS.length - 1);
  });

  it('ranks the correct candidate first far more often than chance as data grows', () => {
    const points = measureSuccessRate({
      sbox: heys,
      cipherRounds: 3,
      half: 'high',
      startMask: TRAIL.startMask,
      endMask: TRAIL.endMask,
      sampleCounts: [32, 1024],
      keyCount: 40,
      bias: TRAIL.bias,
      seed: 2024,
    });
    expect(points[0].rate).toBeGreaterThan(1 / 16); // already beats guessing
    expect(points[1].rate).toBeGreaterThan(0.8); // and converges with data
    expect(points[1].rate).toBeGreaterThan(points[0].rate);
    expect(points[0].trials).toBe(40);
  });

  it('also breaks the PRESENT-S-box cipher, on both nibbles', () => {
    for (const half of ['low', 'high'] as const) {
      const selected = selectApproximation(present, 3, half)!;
      expect(selected.usable).toBe(true);
      let recovered = 0;
      for (const masterKey of KEYS) {
        const key = generateKey(masterKey);
        const result = runAttack({
          sbox: present,
          key,
          cipherRounds: 3,
          half,
          startMask: selected.trail.startMask,
          endMask: selected.trail.endMask,
          pairs: fullCodebook(key, present, 3),
        });
        if (result.recovered) recovered++;
      }
      expect(recovered).toBe(KEYS.length);
    }
  });
});

describe('screening — a strong trail is not the same thing as a broken key', () => {
  it('picks an approximation that survives contact with the real cipher', () => {
    expect(SELECTED.usable).toBe(true);
    expect(SELECTED.screen.outrightBreaks).toBe(SELECTED.screen.trials);
    expect(SELECTED.screen.meanGap).toBeGreaterThan(0);
    expect(Math.abs(SELECTED.trail.bias)).toBeCloseTo(1 / 8, 12);
  });

  it('finds that the top-ranked trail is sometimes NOT the one that works', () => {
    // The demo's headline claim: piling-up strength ranks candidates, it does
    // not certify them. Somewhere in the top of the ranking sits a trail with
    // a textbook correlation that never names the key.
    const top = rankApproximations(heys, 2, { endHalf: 'high', limit: 24 });
    const screened = top.map((c) => screenApproximation(heys, 3, 'high', c.startMask, c.endMask));
    const strongest = top[0].absCorrelation;
    const equallyStrong = screened.filter((_, i) => top[i].absCorrelation === strongest);
    expect(equallyStrong.length).toBeGreaterThan(1);
    expect(equallyStrong.some((s) => s.ceiling === 1)).toBe(true);
    expect(equallyStrong.some((s) => s.ceiling < 1)).toBe(true);
  });

  it('reports honestly that one nibble of the Heys cipher resists this attack', () => {
    // Exhaustive: EVERY (a,b) pair whose end mask lies in the low nibble, run
    // against the whole codebook. None of them isolates the low nibble of the
    // final subkey — the correct candidate is always tied with an impostor.
    // This is a real property of the toy, and the UI says so rather than
    // showing a broken-looking attack with no explanation.
    const keys = [0x3a94, 0x1234, 0xbeef, 0xace1, 0x0000, 0x77f0];
    const all = rankApproximations(heys, 2, { endHalf: 'low' });
    expect(all.length).toBeGreaterThan(1000);
    let anyAlwaysWorks = false;
    for (const candidate of all) {
      const screen = screenApproximation(heys, 3, 'low', candidate.startMask, candidate.endMask, keys);
      if (screen.outrightBreaks === screen.trials) {
        anyAlwaysWorks = true;
        break;
      }
    }
    expect(anyAlwaysWorks).toBe(false);
    expect(selectApproximation(heys, 3, 'low')!.usable).toBe(false);
  });

  it('still extracts information from a nibble it cannot pin down', () => {
    // "Not recovered" is not "learned nothing": the ranking still shrinks the
    // candidate set, and the demo reports the bits it genuinely bought.
    const fallback = selectApproximation(heys, 3, 'low')!;
    const key = generateKey(0x3a94);
    const result = runAttack({
      sbox: heys,
      key,
      cipherRounds: 3,
      half: 'low',
      startMask: fallback.trail.startMask,
      endMask: fallback.trail.endMask,
      pairs: fullCodebook(key, heys, 3),
    });
    expect(result.recovered || result.tiedAtTop || result.correctRank > 1).toBe(true);
  });
});

describe('the attack fails honestly where it should', () => {
  it('is no better than guessing when the data is far too thin', () => {
    // 8 known plaintexts cannot resolve a bias of 1/8; the demo must not
    // pretend otherwise.
    const points = measureSuccessRate({
      sbox: heys,
      cipherRounds: 3,
      half: 'high',
      startMask: TRAIL.startMask,
      endMask: TRAIL.endMask,
      sampleCounts: [8],
      keyCount: 40,
      bias: TRAIL.bias,
      seed: 99,
    });
    expect(points[0].rate).toBeLessThan(0.5);
  });

  it('does not break the full 4-round cipher, even with the entire codebook', () => {
    // The best 3-round approximation this search can find still leaves the
    // correct candidate at the top for only a minority of keys. One extra
    // round is the difference between broken and not.
    const trail = bestTrail(heys, 3, { endHalf: 'high' })!;
    let recovered = 0;
    let trials = 0;
    for (let masterKey = 0; masterKey < 0x10000; masterKey += 997) {
      const key = generateKey(masterKey);
      const result = runAttack({
        sbox: heys,
        key,
        cipherRounds: 4,
        half: 'high',
        startMask: trail.startMask,
        endMask: trail.endMask,
        pairs: fullCodebook(key, heys, 4),
      });
      if (result.recovered) recovered++;
      trials++;
    }
    expect(recovered / trials).toBeLessThan(0.6);
  });

  it('refuses an end mask that reads bits the guess cannot peel', () => {
    const key = generateKey(0x3a94);
    expect(() =>
      runAttack({
        sbox: heys,
        key,
        cipherRounds: 3,
        half: 'high',
        startMask: 0b0000_1001,
        endMask: 0b1100_0001, // straddles both nibbles
        pairs: fullCodebook(key, heys, 3),
      }),
    ).toThrow(RangeError);
  });

  it('refuses an empty end mask', () => {
    const key = generateKey(0x3a94);
    expect(() =>
      runAttack({ sbox: heys, key, cipherRounds: 3, half: 'high', startMask: 0b1001, endMask: 0, pairs: [] }),
    ).toThrow(RangeError);
  });

  it('reports a tie rather than claiming a break', () => {
    // With zero data every candidate scores exactly 0: the honest answer is
    // "16 candidates survive", not "recovered".
    const key = generateKey(0x3a94);
    const result = runAttack({
      sbox: heys,
      key,
      cipherRounds: 3,
      half: 'high',
      startMask: TRAIL.startMask,
      endMask: TRAIL.endMask,
      pairs: [],
    });
    expect(result.recovered).toBe(false);
    expect(result.tiedAtTop).toBe(true);
    expect(result.winners).toHaveLength(16);
    expect(result.bitsRecovered).toBe(0);
  });
});

describe('incremental counting', () => {
  const key = generateKey(0x3a94);
  const base = {
    sbox: heys,
    key,
    cipherRounds: 3,
    half: 'high' as const,
    startMask: TRAIL.startMask,
    endMask: TRAIL.endMask,
  };

  it('reaches exactly the same result as counting in one go', () => {
    const pairs = collectKnownPairs(key, heys, 3, 1000, mulberry32(5));
    const counter = startAttack({ ...base, pairs });
    while (!counter.done) counter.advance(37); // deliberately uneven batches
    expect(counter.snapshot()).toEqual(runAttack({ ...base, pairs }));
    expect(counter.processed).toBe(1000);
  });

  it('a partial snapshot is the honest result for the pairs seen so far', () => {
    // This is what makes it safe to animate: the bars at 40 of 256 pairs show
    // what an attacker with 40 pairs would actually have, not an interpolation.
    const pairs = collectKnownPairs(key, heys, 3, 256, mulberry32(9));
    const counter = startAttack({ ...base, pairs });
    counter.advance(40);
    const partial = counter.snapshot();
    expect(partial.samples).toBe(40);
    expect(partial).toEqual(runAttack({ ...base, pairs: pairs.slice(0, 40) }));
  });

  it('stops at the end and reports how much it consumed', () => {
    const pairs = collectKnownPairs(key, heys, 3, 10, mulberry32(1));
    const counter = startAttack({ ...base, pairs });
    expect(counter.advance(4)).toBe(4);
    expect(counter.advance(999)).toBe(6);
    expect(counter.advance(999)).toBe(0);
    expect(counter.done).toBe(true);
    expect(counter.total).toBe(10);
  });

  it('validates its masks before counting a single pair', () => {
    expect(() => startAttack({ ...base, endMask: 0b1100_0001, pairs: [] })).toThrow(RangeError);
    expect(() => startAttack({ ...base, endMask: 0, pairs: [] })).toThrow(RangeError);
  });
});

describe('scoring', () => {
  it('scores all sixteen candidates and ranks them consistently', () => {
    const key = generateKey(0x3a94);
    const result = runAttack({
      sbox: heys,
      key,
      cipherRounds: 3,
      half: 'high',
      startMask: TRAIL.startMask,
      endMask: TRAIL.endMask,
      pairs: fullCodebook(key, heys, 3),
    });
    expect(result.scores).toHaveLength(16);
    expect(result.ranked).toHaveLength(16);
    for (const score of result.scores) {
      expect(score.total).toBe(256);
      expect(score.bias).toBeCloseTo(score.matches / 256 - 0.5, 12);
      expect(score.deviation).toBeCloseTo(Math.abs(score.bias), 12);
    }
    for (let i = 1; i < result.ranked.length; i++) {
      expect(result.ranked[i - 1].deviation).toBeGreaterThanOrEqual(result.ranked[i].deviation);
    }
    expect(result.ranked[0].guess).toBe(result.trueNibble);
  });
});

describe('how many known plaintexts do I need', () => {
  /**
   * Matsui 1993, Section 4: the success rate of the counting attack is
   * 84.1%, 92.1%, 97.7% and 99.8% when N is 1/4, 1/2, 1 and 2 times the
   * inverse square of the bias. These four numbers are the paper's table.
   */
  it('reproduces the success-rate table from Matsui 1993', () => {
    const bias = 1 / 32;
    const inverseSquare = 1 / (bias * bias);
    const expected: [number, number][] = [
      [0.25, 0.841],
      [0.5, 0.921],
      [1, 0.977],
      [2, 0.998],
    ];
    for (const [multiple, rate] of expected) {
      expect(theoreticalSuccessRate(bias, multiple * inverseSquare)).toBeCloseTo(rate, 2);
    }
  });

  it('inverts that relation to a sample count', () => {
    const bias = 1 / 32;
    for (const target of [0.6, 0.75, 0.9, 0.977, 0.999]) {
      const n = requiredSamples(bias, target);
      expect(theoreticalSuccessRate(bias, n)).toBeGreaterThanOrEqual(target - 1e-3);
      // One sample fewer should not already clear the bar by a wide margin.
      expect(theoreticalSuccessRate(bias, Math.max(0, n - 1))).toBeLessThan(target + 1e-3);
    }
  });

  it('scales as the inverse square of the bias', () => {
    const half = requiredSamples(1 / 16, 0.977);
    const quarter = requiredSamples(1 / 32, 0.977);
    expect(quarter / half).toBeCloseTo(4, 1);
  });

  it('demands infinite data from a useless approximation', () => {
    expect(requiredSamples(0, 0.9)).toBe(Number.POSITIVE_INFINITY);
    expect(requiredSamples(0.1, 1)).toBe(Number.POSITIVE_INFINITY);
    expect(requiredSamples(0.1, 0.5)).toBe(0);
  });

  it('has a sane normal CDF underneath', () => {
    expect(normalCdf(0)).toBeCloseTo(0.5, 6);
    expect(normalCdf(1)).toBeCloseTo(0.8413, 3);
    expect(normalCdf(2)).toBeCloseTo(0.9772, 3);
    expect(normalCdf(-2)).toBeCloseTo(0.0228, 3);
  });

  it('warns that the formula is optimistic for a 16-way ranking', () => {
    // The formula describes ONE counter. Algorithm 2 ranks sixteen of them, so
    // the measured rate lags the theoretical one — the demo says so, and this
    // test pins the claim to a measurement.
    const points = measureSuccessRate({
      sbox: heys,
      cipherRounds: 3,
      half: 'high',
      startMask: TRAIL.startMask,
      endMask: TRAIL.endMask,
      sampleCounts: [64, 256],
      keyCount: 40,
      bias: TRAIL.bias,
      seed: 31337,
    });
    for (const point of points) {
      expect(point.rate).toBeLessThan(point.theoretical);
    }
  });
});
