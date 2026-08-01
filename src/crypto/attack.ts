/**
 * Matsui's Algorithm 2 — key recovery from a linear approximation.
 *
 * Given a linear approximation  <a,P> XOR <b,u_R> = 0  that holds with bias
 * eps over the first R-1 rounds, the attacker:
 *
 *   1. collects N KNOWN plaintext/ciphertext pairs (no chosen inputs, no
 *      oracle games — just traffic they happened to see);
 *   2. for each of the 16 candidate values of one nibble of the final subkey,
 *      peels the last substitution off every ciphertext;
 *   3. counts how often the approximation holds under that candidate;
 *   4. ranks the candidates by |count - N/2|.
 *
 * The correct candidate un-does the real last round, so the counter inherits
 * the approximation's bias. A wrong candidate scrambles the last round, and
 * its counter should look like a coin flip. "Should" is doing real work in
 * that sentence — it is the wrong-key randomisation *hypothesis*, and on a
 * block this small it is only approximately true. The demo measures the
 * hypothesis rather than assuming it.
 */

import { dot, type Sbox } from './sbox.js';
import {
  generateKey,
  peelLastRoundNibble,
  placeNibble,
  takeNibble,
  encrypt,
  type NibbleHalf,
  type SpnKey,
} from './spn.js';
import { mulberry32, type Rng } from './rng.js';
import { rankApproximations, trailBetween, type Trail } from './trail.js';

export interface KnownPair {
  readonly plaintext: number;
  readonly ciphertext: number;
}

/**
 * Known-plaintext collection: plaintexts drawn uniformly at random (with
 * replacement — the attacker takes what traffic gives them), encrypted under
 * the secret key. The attacker never chooses a plaintext; that is the whole
 * practical advantage of linear over differential cryptanalysis.
 */
export function collectKnownPairs(
  key: SpnKey,
  sbox: Sbox,
  cipherRounds: number,
  count: number,
  rng: Rng,
): KnownPair[] {
  const pairs: KnownPair[] = new Array(count);
  for (let i = 0; i < count; i++) {
    const plaintext = rng.nextByte();
    pairs[i] = { plaintext, ciphertext: encrypt(plaintext, key, sbox, cipherRounds) };
  }
  return pairs;
}

/** Every plaintext exactly once — the entire population, no sampling error. */
export function fullCodebook(key: SpnKey, sbox: Sbox, cipherRounds: number): KnownPair[] {
  const pairs: KnownPair[] = new Array(256);
  for (let p = 0; p < 256; p++) pairs[p] = { plaintext: p, ciphertext: encrypt(p, key, sbox, cipherRounds) };
  return pairs;
}

export interface GuessScore {
  readonly guess: number;
  /** How often the approximation held under this candidate. */
  readonly matches: number;
  readonly total: number;
  /** matches/total - 1/2, signed. */
  readonly bias: number;
  /** |bias| — the ranking statistic. */
  readonly deviation: number;
}

export interface AttackResult {
  /** Indexed by candidate value, 0..15. */
  readonly scores: readonly GuessScore[];
  /** Sorted by deviation, highest first. */
  readonly ranked: readonly GuessScore[];
  /** Every candidate tied for the top deviation. */
  readonly winners: readonly number[];
  readonly trueNibble: number;
  /** 1-based rank of the correct candidate; ties share the best rank. */
  readonly correctRank: number;
  /** The correct candidate stands alone at the top — an outright break. */
  readonly recovered: boolean;
  /** Correct candidate is tied for the top: the search space shrank, no more. */
  readonly tiedAtTop: boolean;
  readonly samples: number;
  /** Bits of the 16-candidate space eliminated (4 bits = fully determined). */
  readonly bitsRecovered: number;
}

export interface AttackOptions {
  readonly sbox: Sbox;
  readonly key: SpnKey;
  readonly cipherRounds: number;
  readonly half: NibbleHalf;
  readonly startMask: number;
  readonly endMask: number;
  readonly pairs: readonly KnownPair[];
}

const TIE_EPSILON = 1e-12;

/**
 * An attack in progress. The counters are the real thing at every point —
 * `snapshot()` after 40 of 256 pairs reports exactly what an attacker who had
 * seen 40 pairs would have. That is what lets the UI animate the count without
 * animating a fiction: the bars move because the numbers moved.
 */
export interface AttackCounter {
  /** Pairs consumed so far. */
  readonly processed: number;
  readonly total: number;
  readonly done: boolean;
  /** Consume the next `count` pairs. Returns how many were actually consumed. */
  advance(count: number): number;
  /** The result as it stands right now. */
  snapshot(): AttackResult;
}

export function startAttack(options: AttackOptions): AttackCounter {
  const { sbox, key, cipherRounds, half, startMask, endMask, pairs } = options;
  const strayBits = half === 'low' ? endMask & 0xf0 : endMask & 0x0f;
  if (strayBits !== 0) {
    throw new RangeError(
      `end mask 0x${endMask.toString(16)} reads bits outside the ${half} nibble; a one-nibble guess cannot peel it`,
    );
  }
  if ((endMask & 0xff) === 0) throw new RangeError('end mask must be non-zero');

  const counts = new Array<number>(16).fill(0);
  let processed = 0;

  // The 16 peeled nibbles depend only on the ciphertext, so precomputing the
  // per-ciphertext parities once keeps each batch cheap enough to run inside a
  // frame without dropping the count.
  const parityFor = new Uint8Array(256 * 16);
  for (let c = 0; c < 256; c++) {
    for (let guess = 0; guess < 16; guess++) {
      const nibble = peelLastRoundNibble(c, guess, half, sbox);
      parityFor[c * 16 + guess] = dot(endMask, placeNibble(nibble, half));
    }
  }

  const advance = (count: number): number => {
    const limit = Math.min(processed + Math.max(0, count), pairs.length);
    let consumed = 0;
    for (; processed < limit; processed++) {
      const { plaintext, ciphertext } = pairs[processed];
      const lhs = dot(startMask, plaintext);
      const base = (ciphertext & 0xff) * 16;
      for (let guess = 0; guess < 16; guess++) {
        if (lhs === parityFor[base + guess]) counts[guess]++;
      }
      consumed++;
    }
    return consumed;
  };

  return {
    get processed() {
      return processed;
    },
    total: pairs.length,
    get done() {
      return processed >= pairs.length;
    },
    advance,
    snapshot: () => score(counts, processed, key, cipherRounds, half),
  };
}

export function runAttack(options: AttackOptions): AttackResult {
  const counter = startAttack(options);
  counter.advance(options.pairs.length);
  return counter.snapshot();
}

function score(
  counts: readonly number[],
  total: number,
  key: SpnKey,
  cipherRounds: number,
  half: NibbleHalf,
): AttackResult {
  const scores: GuessScore[] = counts.map((matches, guess) => {
    const bias = total === 0 ? 0 : matches / total - 0.5;
    return { guess, matches, total, bias, deviation: Math.abs(bias) };
  });

  const ranked = [...scores].sort((x, y) => y.deviation - x.deviation || x.guess - y.guess);
  const top = ranked[0].deviation;
  const winners = scores.filter((s) => Math.abs(s.deviation - top) <= TIE_EPSILON).map((s) => s.guess);
  const trueNibble = takeNibble(key.subkeys[cipherRounds], half);
  const correctScore = scores[trueNibble];
  const better = scores.filter((s) => s.deviation > correctScore.deviation + TIE_EPSILON).length;
  const correctRank = better + 1;
  const correctAtTop = Math.abs(correctScore.deviation - top) <= TIE_EPSILON;

  return {
    scores,
    ranked,
    winners,
    trueNibble,
    correctRank,
    recovered: correctAtTop && winners.length === 1,
    tiedAtTop: correctAtTop && winners.length > 1,
    samples: total,
    bitsRecovered: correctAtTop ? Math.log2(16 / winners.length) : 0,
  };
}

/* ------------------------------------------------------------------ *
 * Screening: does this approximation actually separate the right key?
 * ------------------------------------------------------------------ */

/**
 * The wrong-key randomisation hypothesis says a wrong guess scrambles the last
 * round, so its counter should be unbiased. On a real 64- or 128-bit cipher
 * that is an excellent approximation. On an 8-bit toy it is not always true,
 * and a trail with a textbook-perfect correlation can still fail to name the
 * key — several candidates tie forever, no matter how much data you collect.
 *
 * So candidates get screened rather than trusted: run the attack on the FULL
 * codebook (no sampling error at all) for a spread of keys and see whether the
 * correct candidate actually ends up alone at the top.
 */
export interface ScreenResult {
  readonly startMask: number;
  readonly endMask: number;
  readonly trials: number;
  /** Trials where the correct candidate stood alone at the top. */
  readonly outrightBreaks: number;
  /** Trials where it was at least tied for the top. */
  readonly correctInTop: number;
  /** outrightBreaks / trials, with the entire codebook — the ceiling on success. */
  readonly ceiling: number;
  /** Mean |bias| the correct candidate showed. */
  readonly meanBias: number;
  /** Mean gap between the correct candidate and the best wrong one. Negative = hopeless. */
  readonly meanGap: number;
}

export const SCREEN_KEYS: readonly number[] = [
  0x0000, 0x3a94, 0x1234, 0xbeef, 0xace1, 0xffff, 0x77f0, 0x5a5a, 0x9c3d, 0x02b8, 0xd471, 0x6e29,
];

export function screenApproximation(
  sbox: Sbox,
  cipherRounds: number,
  half: NibbleHalf,
  startMask: number,
  endMask: number,
  masterKeys: readonly number[] = SCREEN_KEYS,
): ScreenResult {
  let outrightBreaks = 0;
  let correctInTop = 0;
  let biasSum = 0;
  let gapSum = 0;

  for (const masterKey of masterKeys) {
    const key = generateKey(masterKey);
    const result = runAttack({
      sbox,
      key,
      cipherRounds,
      half,
      startMask,
      endMask,
      pairs: fullCodebook(key, sbox, cipherRounds),
    });
    if (result.recovered) outrightBreaks++;
    if (result.recovered || result.tiedAtTop) correctInTop++;
    const correct = result.scores[result.trueNibble].deviation;
    const bestWrong = Math.max(
      ...result.scores.filter((s) => s.guess !== result.trueNibble).map((s) => s.deviation),
    );
    biasSum += correct;
    gapSum += correct - bestWrong;
  }

  const trials = masterKeys.length;
  return {
    startMask,
    endMask,
    trials,
    outrightBreaks,
    correctInTop,
    ceiling: outrightBreaks / trials,
    meanBias: biasSum / trials,
    meanGap: gapSum / trials,
  };
}

export interface SelectedApproximation {
  readonly trail: Trail;
  readonly screen: ScreenResult;
  /** How many ranked candidates were screened before this one was chosen. */
  readonly screened: number;
  /** The candidate's position in the piling-up ranking, 1-based. */
  readonly rank: number;
  /** True when a candidate that always names the key was found. */
  readonly usable: boolean;
}

/**
 * Pick the approximation the attack panel should ship with: walk the
 * piling-up ranking from the top, screen each candidate against the real
 * cipher, and take the first one that names the key for every screening key.
 * If none does — which genuinely happens for one nibble of this toy — return
 * the best of a bad lot and let the UI say so.
 */
export function selectApproximation(
  sbox: Sbox,
  cipherRounds: number,
  half: NibbleHalf,
  limit = 24,
): SelectedApproximation | null {
  const approxRounds = cipherRounds - 1;
  const candidates = rankApproximations(sbox, approxRounds, { endHalf: half, limit });
  if (candidates.length === 0) return null;

  let bestFallback: { screen: ScreenResult; rank: number } | null = null;

  for (let i = 0; i < candidates.length; i++) {
    const candidate = candidates[i];
    const screen = screenApproximation(sbox, cipherRounds, half, candidate.startMask, candidate.endMask);
    if (screen.outrightBreaks === screen.trials) {
      const trail = trailBetween(sbox, approxRounds, candidate.startMask, candidate.endMask);
      if (!trail) continue;
      return { trail, screen, screened: i + 1, rank: i + 1, usable: true };
    }
    if (
      bestFallback === null ||
      screen.ceiling > bestFallback.screen.ceiling ||
      (screen.ceiling === bestFallback.screen.ceiling && screen.meanGap > bestFallback.screen.meanGap)
    ) {
      bestFallback = { screen, rank: i + 1 };
    }
  }

  if (!bestFallback) return null;
  const trail = trailBetween(sbox, approxRounds, bestFallback.screen.startMask, bestFallback.screen.endMask);
  if (!trail) return null;
  return {
    trail,
    screen: bestFallback.screen,
    screened: candidates.length,
    rank: bestFallback.rank,
    usable: false,
  };
}

/* ------------------------------------------------------------------ *
 * How many known plaintexts do I need?
 * ------------------------------------------------------------------ */

/**
 * Matsui's Algorithm 1 analysis. The counter is Binomial(N, 1/2 + eps), so the
 * probability of reading the bias in the right direction is Phi(2*eps*sqrt(N)).
 * Inverting gives the sample size for a target success rate:
 *
 *     N = ( Phi^-1(success) / (2*eps) )^2
 *
 * At eps^-2, 2*eps*sqrt(N) = 2 and the success rate is Phi(2) = 97.7% — the
 * familiar "N is about the inverse square of the bias" rule of thumb.
 */
export function requiredSamples(bias: number, successRate: number): number {
  if (bias === 0) return Number.POSITIVE_INFINITY;
  if (successRate <= 0.5) return 0;
  if (successRate >= 1) return Number.POSITIVE_INFINITY;
  const z = inverseNormalCdf(successRate);
  return Math.ceil(Math.pow(z / (2 * Math.abs(bias)), 2));
}

/** Theoretical Algorithm-1 success rate for N samples at this bias. */
export function theoreticalSuccessRate(bias: number, samples: number): number {
  return normalCdf(2 * Math.abs(bias) * Math.sqrt(samples));
}

/** Abramowitz & Stegun 7.1.26 — |error| < 1.5e-7, ample for a sample-size hint. */
function erf(x: number): number {
  const sign = x < 0 ? -1 : 1;
  const z = Math.abs(x);
  const t = 1 / (1 + 0.3275911 * z);
  const y =
    1 -
    ((((1.061405429 * t - 1.453152027) * t + 1.421413741) * t - 0.284496736) * t + 0.254829592) *
      t *
      Math.exp(-z * z);
  return sign * y;
}

export function normalCdf(x: number): number {
  return 0.5 * (1 + erf(x / Math.SQRT2));
}

/** Inverted by bisection — slower than a rational fit, and obviously correct. */
export function inverseNormalCdf(p: number): number {
  let lo = -10;
  let hi = 10;
  for (let i = 0; i < 200; i++) {
    const mid = (lo + hi) / 2;
    if (normalCdf(mid) < p) lo = mid;
    else hi = mid;
  }
  return (lo + hi) / 2;
}

/* ------------------------------------------------------------------ *
 * Measuring the attack instead of trusting the formula
 * ------------------------------------------------------------------ */

export interface SuccessPoint {
  readonly samples: number;
  readonly trials: number;
  readonly outrightBreaks: number;
  readonly correctInTop: number;
  /** Fraction of trials where the correct candidate stood alone at the top. */
  readonly rate: number;
  /** The theoretical Algorithm-1 rate at this sample count, for comparison. */
  readonly theoretical: number;
}

export interface MeasureOptions {
  readonly sbox: Sbox;
  readonly cipherRounds: number;
  readonly half: NibbleHalf;
  readonly startMask: number;
  readonly endMask: number;
  readonly sampleCounts: readonly number[];
  readonly keyCount: number;
  readonly bias: number;
  readonly seed: number;
  /** Called after each individual attack, so a worker can report real progress. */
  readonly onProgress?: (completed: number, total: number) => void;
}

/**
 * Run the whole attack end to end over many random keys and report how often
 * it actually worked. This is the honest counterweight to the sample-size
 * formula: the formula describes one counter's statistics, the experiment
 * describes the ranking of sixteen competing counters.
 */
export function measureSuccessRate(options: MeasureOptions): SuccessPoint[] {
  const { sbox, cipherRounds, half, startMask, endMask, sampleCounts, keyCount, bias, seed, onProgress } =
    options;
  const rng = mulberry32(seed);
  const masterKeys: number[] = [];
  for (let i = 0; i < keyCount; i++) masterKeys.push(((rng.nextByte() << 8) | rng.nextByte()) & 0xffff);
  const totalTrials = sampleCounts.length * keyCount;
  let completed = 0;

  return sampleCounts.map((samples) => {
    let outrightBreaks = 0;
    let correctInTop = 0;
    for (let i = 0; i < masterKeys.length; i++) {
      const key = generateKey(masterKeys[i]);
      const dataRng = mulberry32((seed ^ (samples * 0x9e3779b1) ^ (i * 0x85ebca6b)) >>> 0);
      const pairs = collectKnownPairs(key, sbox, cipherRounds, samples, dataRng);
      const result = runAttack({ sbox, key, cipherRounds, half, startMask, endMask, pairs });
      if (result.recovered) outrightBreaks++;
      if (result.recovered || result.tiedAtTop) correctInTop++;
      completed++;
      onProgress?.(completed, totalTrials);
    }
    return {
      samples,
      trials: masterKeys.length,
      outrightBreaks,
      correctInTop,
      rate: outrightBreaks / masterKeys.length,
      theoretical: theoreticalSuccessRate(bias, samples),
    };
  });
}
