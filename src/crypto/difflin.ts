/**
 * Differential–linear composition on the shared toy SPN.
 *
 * Langford and Hellman's CRYPTO '94 attack joins a differential prefix to a
 * linear suffix. In their base construction the relevant prefix parity
 * condition holds with probability one, and a suffix approximation of bias ε
 * gives pair bias 2·ε². Biham, Dunkelman and Keller's published ASIACRYPT
 * 2002 enhancement admits a prefix condition that holds with probability p
 * and assumes the remaining pairs have random output parities. Under that
 * extra assumption the pair relation
 *
 *     <λout, v> ⊕ <λout, v'> = <λin, ΔY>
 *
 * holds with probability 1/2 + 2·p·ε². The p-weighted enhancement is a
 * *population* heuristic with assumptions attached, and this module computes
 * all three numbers it can be compared against:
 *
 *   1. the naive heuristic      2·p·ε²          (assumes off-path pairs wash out)
 *   2. the path-aware estimate   Σ w_i·bias_i    (enumerates the DDT row, but
 *      still assumes uniform intermediate values within each path)
 *   3. the measured value, from real chosen pairs on the real cipher.
 *
 * On this toy cipher the three disagree in ways the exhibit makes visible.
 * For the aligned design every path through the DDT row leaves the same value
 * of <λin, Δ'>, so the off-path assumption fails *upward*. The path-aware
 * estimate is 9/32; the real full-codebook measurement is either 1/4 or 5/16,
 * depending on the key. For the cancelled design, paths whose right-hand side
 * differs from the designated path contribute with the opposite sign. Their
 * weighted contributions cancel exactly: the path-aware estimate and the real
 * measurement are zero although the naive heuristic promises 1/16.
 *
 * The lesson runs on one fixed 3-round construction (the same reduced-round
 * option the cockpit offers). An 8-bit block has only 128 distinct pairs with
 * a fixed nonzero difference. This exhibit makes no claim that its selected
 * masks are optimal for four rounds or that it attacks the full cipher.
 *
 * NOT PRODUCTION CRYPTOGRAPHY. The cipher is broken by definition; the point
 * is to watch the composed statistic, its assumptions, and their failure.
 *
 * Primary sources: S. K. Langford, M. E. Hellman, "Differential–Linear
 * Cryptanalysis", CRYPTO '94, LNCS 839, pp. 17–25; E. Biham, O. Dunkelman,
 * N. Keller, "Enhancing Differential-Linear Cryptanalysis", ASIACRYPT 2002,
 * LNCS 2501, pp. 254–266.
 */

import { dot, type Sbox } from './sbox.js';
import { permute } from './permutation.js';
import { encrypt, generateKey, type SpnKey } from './spn.js';
import { latFor, roundCorrelation } from './trail.js';

/** The composition targets the 3-round reduced form of the shared toy SPN. */
export const DL_ROUNDS = 3;

/** Chosen plaintext difference: 0x0b on the low nibble, high nibble untouched. */
export const DL_DX = 0x0b;

export interface DlDesign {
  readonly name: 'aligned' | 'cancelled';
  /** Mask on the joining state (the round-2 input). */
  readonly lambdaIn: number;
  /** Mask on the round-3 S-box input — the state the subkey peel recovers. */
  readonly lambdaOut: number;
  readonly label: string;
  readonly note: string;
}

/**
 * The aligned design: λin reads bit 1 of the joining state. Bit 1 comes from
 * S-box output bit 5, which a low-nibble difference never touches, so every
 * path through the DDT row of 0x0b keeps <λin, Δ'> = 0 — the pair relation
 * aligns on ALL paths, not just the designated one.
 */
export const ALIGNED: DlDesign = {
  name: 'aligned',
  lambdaIn: 0x02,
  lambdaOut: 0x4c,
  label: 'Aligned composition',
  note: 'λin = 0x02 reads a bit of the joining state that no path of this DDT row can move.',
};

/**
 * The control: λin reads bit 2, which different paths of the same DDT row
 * move in opposite directions. The heuristic promises signal; the paths cancel
 * and the measured bias is exactly zero.
 */
export const CANCELLED: DlDesign = {
  name: 'cancelled',
  lambdaIn: 0x04,
  lambdaOut: 0xc0,
  label: 'Cancelled composition (control)',
  note: 'λin = 0x04 reads a bit the DDT row moves both ways — signed path contributions cancel and repair the naive prediction.',
};

export const DL_BUDGETS: readonly number[] = [16, 32, 64, 96, 128];
export const DL_DEFAULT_BUDGET = 96;

export interface DdtTable {
  /** ddt[din][dout] = number of x in 0..15 with S(x)⊕S(x⊕din) = dout. */
  readonly table: readonly (readonly number[])[];
}

/** The difference distribution table of a 4-bit S-box, by brute force. */
export function buildDdt(sbox: Sbox): DdtTable {
  const table: number[][] = Array.from({ length: 16 }, () => new Array<number>(16).fill(0));
  for (let din = 0; din < 16; din++) {
    for (let x = 0; x < 16; x++) {
      table[din][sbox.table[x] ^ sbox.table[x ^ din]] += 1;
    }
  }
  return { table };
}

export function ddtEntry(ddt: DdtTable, din: number, dout: number): number {
  if (!Number.isInteger(din) || din < 0 || din > 15 || !Number.isInteger(dout) || dout < 0 || dout > 15) {
    throw new RangeError(`DDT indices must be 4-bit integers, got ${din}/${dout}`);
  }
  return ddt.table[din][dout];
}

export interface PrefixPath {
  /** S-box output difference on the active (low) nibble. */
  readonly sboxDiff: number;
  /** Fraction of round-1 pairs that take this path (DDT entry / 16). */
  readonly weight: number;
  /** Difference at the joining state after the round-1 permutation. */
  readonly joiningDiff: number;
  /** The suffix's input mask evaluated on this path's joining difference. */
  readonly lambdaInDot: number;
}

/**
 * Every path the chosen difference can take through round 1: the nonzero
 * entries of DDT[ΔX], carried through the bit permutation to the joining
 * state. Key-independent by the DDT property: x ↦ x⊕K1 permutes the pairs.
 */
export function prefixPaths(sbox: Sbox, design: DlDesign, dX: number): PrefixPath[] {
  if (!Number.isInteger(dX) || dX <= 0 || dX > 0xff || (dX & 0xf0) !== 0) {
    throw new RangeError(`this lesson's ΔX is a nonzero low-nibble difference, got 0x${dX.toString(16)}`);
  }
  const ddt = buildDdt(sbox);
  const paths: PrefixPath[] = [];
  for (let diff = 0; diff < 16; diff++) {
    const count = ddtEntry(ddt, dX & 0xf, diff);
    if (count === 0) continue;
    paths.push({
      sboxDiff: diff,
      weight: count / 16,
      joiningDiff: permute(diff),
      lambdaInDot: dot(design.lambdaIn, permute(diff)),
    });
  }
  return paths;
}

/** The designated differential: the heaviest entry of the prefix's DDT row. */
export function designatedPath(sbox: Sbox, design: DlDesign, dX: number): PrefixPath {
  const paths = prefixPaths(sbox, design, dX);
  let best = paths[0];
  for (const path of paths) if (path.weight > best.weight) best = path;
  return best;
}

/**
 * The chosen pairs (x, x⊕ΔX), ascending, one per unordered pair. All 128 are
 * distinct; a budget below 128 leaves the rest as a holdout the ranking never
 * touches, which the verification step then spends.
 */
export function chosenPairs(dX: number, budget: number): [number, number][] {
  if (!Number.isInteger(dX) || dX <= 0 || dX > 0xff) {
    throw new RangeError(`ΔX must be a nonzero byte, got 0x${dX.toString(16)}`);
  }
  if (!Number.isInteger(budget) || budget < 1 || budget > 128) {
    throw new RangeError(`budget must be an integer in 1..128, got ${budget}`);
  }
  const pairs: [number, number][] = [];
  for (let x = 0; x < 256 && pairs.length < budget; x++) {
    const other = x ^ dX;
    if (x < other) pairs.push([x, other]);
  }
  return pairs;
}

/** Signed correlation of the one-round suffix, from the LAT machinery. */
export function suffixCorrelation(sbox: Sbox, design: DlDesign): number {
  return roundCorrelation(latFor(sbox), design.lambdaIn, design.lambdaOut);
}

/** The Biham–Dunkelman–Keller p-weighted heuristic for the pair-statistic bias. */
export function naiveBias(p: number, suffixCorr: number): number {
  if (p <= 0 || p > 1) throw new RangeError(`differential probability must be in (0, 1], got ${p}`);
  const eps = Math.abs(suffixCorr) / 2;
  return 2 * p * eps * eps;
}

/**
 * Exact pair bias of the suffix for one fixed joining difference, evaluated
 * against the ONE right-hand side used by the attack. Over all 256 uniform
 * values of the joining state, count how often that fixed relation holds and
 * subtract one half. A path whose own <λin, Δ'> differs from `rhs` therefore
 * contributes with the opposite sign. Using each path's own right-hand side
 * would silently change the attack equation from row to row.
 *
 * This is a *measurement* of the cipher, not a formula. Key-dependent
 * constants cancel: K2 translates both texts of a pair together and K3 is
 * XORed into both peeled masks, so the pair statistic is untouched by both.
 */
export function pathPairBias(
  sbox: Sbox,
  design: DlDesign,
  joiningDiff: number,
  rhs: number,
): number {
  if (rhs !== 0 && rhs !== 1) throw new RangeError(`pair-relation RHS must be one bit, got ${rhs}`);
  let agree = 0;
  for (let u = 0; u < 256; u++) {
    const v = suffixMap(sbox, u);
    const vOther = suffixMap(sbox, u ^ joiningDiff);
    if ((dot(design.lambdaOut, v) ^ dot(design.lambdaOut, vOther) ^ rhs) === 0) agree += 1;
  }
  return agree / 256 - 0.5;
}

/** Round 2 alone: joining state in, round-3 S-box input out (keyless core). */
function suffixMap(sbox: Sbox, u: number): number {
  const hi = sbox.table[(u >> 4) & 0xf];
  const lo = sbox.table[u & 0xf];
  return permute((hi << 4) | lo);
}

/**
 * The path-aware estimate: sum each DDT-row path's exact uniform-u pair bias,
 * weighted by the path's share of the pairs. It assumes the joining values are
 * uniform within each path. The aligned design's real key-dependent population
 * (1/4 or 5/16 rather than 9/32) shows that assumption is not exact here; the
 * control instead demonstrates why the off-path-random assumption can fail.
 */
export function pathAwareBias(sbox: Sbox, design: DlDesign, dX: number): number {
  const rhs = designatedPath(sbox, design, dX).lambdaInDot;
  let total = 0;
  for (const path of prefixPaths(sbox, design, dX)) {
    total += path.weight * pathPairBias(sbox, design, path.joiningDiff, rhs);
  }
  return total;
}

/** Which last-round key bits this suffix statistic can actually observe. */
export function subkeyTargetMask(design: DlDesign): number {
  const high = (design.lambdaOut & 0xf0) !== 0;
  const low = (design.lambdaOut & 0x0f) !== 0;
  if (!high && !low) throw new RangeError('the suffix output mask must be nonzero');
  return (high ? 0xf0 : 0) | (low ? 0x0f : 0);
}

/** One canonical guess for each distinguishable last-round-key hypothesis. */
export function subkeyCandidates(design: DlDesign): number[] {
  const mask = subkeyTargetMask(design);
  if (mask === 0xff) return Array.from({ length: 256 }, (_, guess) => guess);
  if (mask === 0xf0) return Array.from({ length: 16 }, (_, guess) => guess << 4);
  return Array.from({ length: 16 }, (_, guess) => guess);
}

export interface DlAttackResult {
  /** Pairs spent on the ranking (the chosen-plaintext budget). */
  readonly attackPairs: number;
  /** Per-guess agreement counts over the attack pairs, index = guess. */
  readonly counts: readonly number[];
  /** Pairs held back from the ranking, spent only by the verification. */
  readonly holdoutPairs: number;
  /** Per-guess agreement counts over the holdout pairs. */
  readonly holdoutCounts: readonly number[];
  /** Canonical hypotheses the selected output mask can distinguish. */
  readonly candidates: readonly number[];
  /** Bits of the final whitening byte visible to the selected output mask. */
  readonly targetMask: number;
  /** The guess with the largest |count − N/2|; ties broken by lowest value. */
  readonly winner: number;
  /** How many OTHER guesses share the winner's excess (a tie at the top). */
  readonly winnerTies: number;
  /** The byte of the final whitening key the ranking is after. */
  readonly trueSubkey: number;
  /** The visible portion of `trueSubkey`, comparable to `winner`. */
  readonly trueTarget: number;
  /** (count − N/2) / N for the true subkey, over the attack pairs. */
  readonly measuredBias: number;
  /** Same, over the holdout, for the winning guess. */
  readonly winnerHoldoutBias: number;
  /** Signed bias of the non-winner with the largest absolute holdout bias. */
  readonly maxOtherHoldoutBias: number;
  /** 'recovered' | 'tied' | 'failed', judged against the true subkey. */
  readonly verdict: 'recovered' | 'tied' | 'failed';
  /** True when the winner's absolute holdout bias beats every other hypothesis. */
  readonly holdoutConfirms: boolean;
}

/**
 * One complete differential–linear ranking on the real cipher.
 *
 * The attacker model: chosen-plaintext access (2·budget oracle queries), the
 * joining state never observed, the true subkey never read until the verdict.
 * Each distinguishable candidate value peels the last round for both texts of
 * every pair; the guess whose peeled pair relation deviates farthest from a
 * coin flip (in either direction) is the winner. A mask spanning both nibbles
 * ranks 256 byte values. A one-nibble mask ranks only 16 nibble values: the
 * unobserved nibble is not falsely presented as recovered key material.
 */
export function runDlAttack(options: {
  readonly sbox: Sbox;
  readonly key: SpnKey;
  readonly design: DlDesign;
  readonly budget: number;
  readonly dX?: number;
}): DlAttackResult {
  const { sbox, key, design, budget } = options;
  const dX = options.dX ?? DL_DX;
  const designated = designatedPath(sbox, design, dX);
  const rhs = dot(design.lambdaIn, designated.joiningDiff);
  const pairs = chosenPairs(dX, 128);
  const attack = pairs.slice(0, budget);
  const holdout = pairs.slice(budget);

  const counts = new Array<number>(256).fill(0);
  const holdoutCounts = new Array<number>(256).fill(0);
  const candidates = subkeyCandidates(design);
  const targetMask = subkeyTargetMask(design);
  const trueSubkey = key.subkeys[DL_ROUNDS] & 0xff;
  const trueTarget = trueSubkey & targetMask;

  const tally = (into: number[], list: readonly [number, number][]): void => {
    for (const [x, other] of list) {
      const c1 = encrypt(x, key, sbox, DL_ROUNDS);
      const c2 = encrypt(other, key, sbox, DL_ROUNDS);
      for (const guess of candidates) {
        const v1 = sbox.inverse[(c1 ^ guess) >> 4] << 4 | sbox.inverse[(c1 ^ guess) & 0xf];
        const v2 = sbox.inverse[(c2 ^ guess) >> 4] << 4 | sbox.inverse[(c2 ^ guess) & 0xf];
        if ((dot(design.lambdaOut, v1) ^ dot(design.lambdaOut, v2) ^ rhs) === 0) into[guess] += 1;
      }
    }
  };
  tally(counts, attack);
  tally(holdoutCounts, holdout);

  const excess = (g: number): number => Math.abs(counts[g] - attack.length / 2);
  let winner = candidates[0];
  for (const g of candidates.slice(1)) if (excess(g) > excess(winner)) winner = g;
  let winnerTies = 0;
  for (const g of candidates) if (g !== winner && excess(g) === excess(winner)) winnerTies += 1;

  const holdoutBias = (g: number): number =>
    holdout.length === 0 ? 0 : (holdoutCounts[g] - holdout.length / 2) / holdout.length;
  let maxOtherHoldoutBias = 0;
  for (const g of candidates) {
    if (g === winner) continue;
    const bias = holdoutBias(g);
    if (Math.abs(bias) > Math.abs(maxOtherHoldoutBias)) maxOtherHoldoutBias = bias;
  }
  const winnerHoldoutBias = holdoutBias(winner);

  const trueAtTop = excess(trueTarget) === excess(winner);
  const verdict: DlAttackResult['verdict'] =
    winner === trueTarget && winnerTies === 0 ? 'recovered' : trueAtTop ? 'tied' : 'failed';

  return {
    attackPairs: attack.length,
    counts,
    holdoutPairs: holdout.length,
    holdoutCounts,
    candidates,
    targetMask,
    winner,
    winnerTies,
    trueSubkey,
    trueTarget,
    measuredBias: (counts[trueTarget] - attack.length / 2) / attack.length,
    winnerHoldoutBias,
    maxOtherHoldoutBias,
    verdict,
    holdoutConfirms: holdout.length > 0 && Math.abs(winnerHoldoutBias) > Math.abs(maxOtherHoldoutBias),
  };
}

export interface DlSuccessPoint {
  readonly budget: number;
  readonly trials: number;
  /** Keys where the true target was in the top absolute-deviation class. */
  readonly wins: number;
  /** Of those, how many were ties at the top rather than outright wins. */
  readonly tiedWins: number;
  readonly rate: number;
}

export interface DlMeasureOptions {
  readonly sbox: Sbox;
  readonly design: DlDesign;
  readonly budgets: readonly number[];
  /**
   * Deterministic: master keys 0, 129, 258, … (i·129 mod 2¹⁶). No randomness
   * anywhere. The odd stride matters: success on this cipher is not uniform
   * over keys — it clusters on key-schedule patterns — so the first 512 keys
   * measured 100% at 64 pairs while the whole 16-bit space measures 84%. The
   * stride disperses this bounded deterministic sample instead of staying in
   * one consecutive key-schedule pocket. It is not a random population sample.
   */
  readonly keyCount: number;
  readonly onProgress?: (completed: number, total: number) => void;
}

/**
 * Measured success rate of the ranking across keys, per budget — the honest
 * counterweight to every heuristic number above. Fully deterministic: the
 * pairs are fixed by the budget, and master key i is (i·129) mod 2¹⁶.
 */
export function measureDlSuccessRate(options: DlMeasureOptions): DlSuccessPoint[] {
  const { sbox, design, budgets, keyCount, onProgress } = options;
  const total = budgets.length * keyCount;
  let completed = 0;
  return budgets.map((budget) => {
    let wins = 0;
    let tiedWins = 0;
    for (let i = 0; i < keyCount; i++) {
      const result = runDlAttack({ sbox, key: generateKey((i * 129) & 0xffff), design, budget });
      if (result.verdict !== 'failed') {
        wins += 1;
        if (result.verdict === 'tied') tiedWins += 1;
      }
      completed += 1;
      onProgress?.(completed, total);
    }
    return { budget, trials: keyCount, wins, tiedWins, rate: wins / keyCount };
  });
}
