/**
 * Linear trails and the piling-up lemma (Matsui 1993, Lemma 2).
 *
 * A linear *trail* is a chain of masks — one per round — that says: "if the
 * approximation with mask alpha_1 holds at round 1, and alpha_2 at round 2,
 * and so on, then plaintext parity <a,P> equals last-round parity <b,u_R>."
 * Each link holds only with some bias; the piling-up lemma says the biases
 * compound:
 *
 *     eps_total = 2^(n-1) * PROD eps_i          (bias form)
 *     c_total   = PROD c_i,  where c = 2*eps    (correlation form)
 *
 * The lemma assumes the rounds behave independently. They do not, exactly, and
 * this module deliberately computes BOTH the lemma's prediction and the true
 * bias (by evaluating the real cipher on all 256 plaintexts) so the gap is
 * visible rather than hidden. That gap is the linear hull effect: many trails
 * connect the same (a,b), and for a given key they add or cancel.
 */

import { correlationOf, buildLat, type LatTable } from './lat.js';
import { permuteMask, permuteMaskInverse } from './permutation.js';
import { dot, type Sbox } from './sbox.js';
import { generateKey, lastRoundInput, takeNibble, type NibbleHalf, type SpnKey } from './spn.js';

export interface TrailStep {
  /** Round number within the approximation, 1-based. */
  readonly round: number;
  /** Mask on the input to this round's S-box layer. */
  readonly inMask: number;
  /** Mask on the output of this round's S-box layer. */
  readonly sboxOutMask: number;
  /** Mask on the input to the next round's S-box layer (= permuted sboxOutMask). */
  readonly outMask: number;
  /** Signed correlation contributed by this round's S-box layer. */
  readonly correlation: number;
  /** Signed bias contributed by this round's S-box layer. */
  readonly bias: number;
  /** Per-nibble detail; an inactive nibble has correlation 1 and contributes nothing. */
  readonly nibbles: readonly {
    readonly half: NibbleHalf;
    readonly inMask: number;
    readonly outMask: number;
    readonly correlation: number;
    readonly active: boolean;
  }[];
}

export interface Trail {
  readonly startMask: number;
  readonly endMask: number;
  readonly steps: readonly TrailStep[];
  /** Product of the per-round correlations — the piling-up lemma's prediction. */
  readonly correlation: number;
  /** correlation / 2 — the piling-up lemma's predicted bias. */
  readonly bias: number;
  /** Number of active S-boxes along the trail (Matsui's cost measure). */
  readonly activeSboxes: number;
}

/** Correlation of one S-box layer, from byte mask alpha to byte mask gamma. */
export function sboxLayerCorrelation(lat: LatTable, alpha: number, gamma: number): number {
  const hi = correlationOf(lat, (alpha >> 4) & 0xf, (gamma >> 4) & 0xf);
  const lo = correlationOf(lat, alpha & 0xf, gamma & 0xf);
  return hi * lo;
}

/**
 * Correlation of one whole round (S-box layer then bit permutation) from the
 * mask on this round's S-box input to the mask on the next round's S-box
 * input. The round-key XOR is absent on purpose: XORing a constant cannot
 * change how often a parity relation holds, it can only flip its sign — which
 * is precisely why key material does not stop a linear approximation.
 */
export function roundCorrelation(lat: LatTable, alpha: number, beta: number): number {
  return sboxLayerCorrelation(lat, alpha, permuteMaskInverse(beta));
}

/* The tables below are pure functions of the S-box, and the UI re-derives them
   on every control change, so each one is computed once and memoised. Two
   entries (one per S-box) is the whole cache — no eviction needed. */
const latCache = new Map<string, LatTable>();
const matrixCache = new Map<string, Float64Array>();

export function latFor(sbox: Sbox): LatTable {
  let lat = latCache.get(sbox.name);
  if (!lat) {
    lat = buildLat(sbox);
    latCache.set(sbox.name, lat);
  }
  return lat;
}

function roundMatrixFor(sbox: Sbox): Float64Array {
  const key = `${sbox.name}:1`;
  let m = matrixCache.get(key);
  if (!m) {
    m = buildRoundMatrix(latFor(sbox));
    matrixCache.set(key, m);
  }
  return m;
}

function bestProductFor(sbox: Sbox, rounds: number): Float64Array {
  const key = `${sbox.name}:best:${rounds}`;
  let m = matrixCache.get(key);
  if (!m) {
    m = bestProductMatrix(roundMatrixFor(sbox), rounds);
    matrixCache.set(key, m);
  }
  return m;
}

/** M[alpha*256 + beta] — the signed one-round correlation matrix. */
export function buildRoundMatrix(lat: LatTable): Float64Array {
  const m = new Float64Array(256 * 256);
  for (let alpha = 0; alpha < 256; alpha++) {
    for (let beta = 0; beta < 256; beta++) {
      m[alpha * 256 + beta] = roundCorrelation(lat, alpha, beta);
    }
  }
  return m;
}

/**
 * Best |correlation| of an r-round trail for EVERY (start, end) mask pair, by
 * repeated max-product composition of the round matrix. This is Matsui's
 * branch-and-bound search done exhaustively — the mask space is only 8 bits
 * wide, so the whole ranking is affordable and nothing has to be sampled.
 */
function bestProductMatrix(m: Float64Array, rounds: number): Float64Array {
  let current = new Float64Array(256 * 256);
  for (let a = 1; a < 256; a++) {
    for (let b = 1; b < 256; b++) current[a * 256 + b] = Math.abs(m[a * 256 + b]);
  }
  for (let d = 2; d <= rounds; d++) {
    const next = new Float64Array(256 * 256);
    for (let a = 1; a < 256; a++) {
      const aRow = a * 256;
      for (let mid = 1; mid < 256; mid++) {
        const left = current[aRow + mid];
        if (left === 0) continue;
        const midRow = mid * 256;
        for (let b = 1; b < 256; b++) {
          const right = m[midRow + b];
          if (right === 0) continue;
          const value = left * Math.abs(right);
          if (value > next[aRow + b]) next[aRow + b] = value;
        }
      }
    }
    current = next;
  }
  return current;
}

export interface ApproximationCandidate {
  readonly startMask: number;
  readonly endMask: number;
  /** |correlation| of the best trail joining them. */
  readonly absCorrelation: number;
  /** |bias| = |correlation| / 2. */
  readonly absBias: number;
}

/**
 * Every (start, end) mask pair that a trail can join, ranked by the piling-up
 * lemma's predicted strength. The attack panel screens the top of this list
 * against the real cipher, because — as the demo shows — a strong trail is a
 * necessary but NOT a sufficient condition for recovering key bits.
 */
export function rankApproximations(
  sbox: Sbox,
  rounds: number,
  options: { endHalf?: NibbleHalf; limit?: number } = {},
): ApproximationCandidate[] {
  const best = bestProductFor(sbox, rounds);
  const out: ApproximationCandidate[] = [];
  for (let a = 1; a < 256; a++) {
    for (let b = 1; b < 256; b++) {
      if (options.endHalf === 'low' && (b & 0xf0) !== 0) continue;
      if (options.endHalf === 'high' && (b & 0x0f) !== 0) continue;
      const value = best[a * 256 + b];
      if (value === 0) continue;
      out.push({ startMask: a, endMask: b, absCorrelation: value, absBias: value / 2 });
    }
  }
  out.sort(
    (x, y) => y.absCorrelation - x.absCorrelation || x.startMask - y.startMask || x.endMask - y.endMask,
  );
  return options.limit === undefined ? out : out.slice(0, options.limit);
}

/**
 * Reconstruct the best trail joining a specific (start, end) mask pair by
 * greedily splitting on the intermediate mask that maximises the product.
 */
export function trailBetween(sbox: Sbox, rounds: number, startMask: number, endMask: number): Trail | null {
  if (rounds < 1) throw new RangeError('rounds must be >= 1');
  const lat = latFor(sbox);
  const m = roundMatrixFor(sbox);
  const prefix: Float64Array[] = [];
  for (let d = 1; d <= rounds; d++) prefix.push(bestProductFor(sbox, d));
  if (prefix[rounds - 1][(startMask & 0xff) * 256 + (endMask & 0xff)] === 0) return null;

  const chain: number[] = [startMask & 0xff];
  let from = startMask & 0xff;
  for (let remaining = rounds; remaining >= 1; remaining--) {
    if (remaining === 1) {
      chain.push(endMask & 0xff);
      break;
    }
    let pick = -1;
    let pickValue = -1;
    for (let mid = 1; mid < 256; mid++) {
      const head = Math.abs(m[from * 256 + mid]);
      if (head === 0) continue;
      const tail = prefix[remaining - 2][mid * 256 + (endMask & 0xff)];
      if (tail === 0) continue;
      const value = head * tail;
      if (value > pickValue + 1e-15) {
        pickValue = value;
        pick = mid;
      }
    }
    if (pick === -1) return null;
    chain.push(pick);
    from = pick;
  }
  return buildTrail(lat, chain);
}

export interface TrailSearchOptions {
  /** Fix the plaintext-side mask. Omit to search all 255 non-zero masks. */
  readonly startMask?: number;
  /** Fix the last-round mask. */
  readonly endMask?: number;
  /** Restrict the last-round mask to one nibble (the nibble the attack peels). */
  readonly endHalf?: NibbleHalf;
}

/**
 * Matsui's search: find the trail with the largest |correlation| over
 * `rounds` S-box layers, by dynamic programming over the 256x256 round
 * correlation matrix. Ties are broken deterministically (smallest start mask,
 * then smallest intermediate mask) so the same cipher always yields the same
 * headline trail.
 */
export function bestTrail(sbox: Sbox, rounds: number, options: TrailSearchOptions = {}): Trail | null {
  if (rounds < 1) throw new RangeError('rounds must be >= 1');
  if (options.startMask !== undefined && options.endMask !== undefined) {
    return trailBetween(sbox, rounds, options.startMask, options.endMask);
  }
  const ranked = rankApproximations(sbox, rounds, { endHalf: options.endHalf });
  const match = ranked.find(
    (c) =>
      (options.startMask === undefined || c.startMask === (options.startMask & 0xff)) &&
      (options.endMask === undefined || c.endMask === (options.endMask & 0xff)),
  );
  return match ? trailBetween(sbox, rounds, match.startMask, match.endMask) : null;
}

/** Rebuild a full Trail (with per-round detail) from a chain of masks. */
export function buildTrail(lat: LatTable, chain: readonly number[]): Trail {
  const steps: TrailStep[] = [];
  let correlation = 1;
  let activeSboxes = 0;

  for (let d = 1; d < chain.length; d++) {
    const inMask = chain[d - 1];
    const outMask = chain[d];
    const sboxOutMask = permuteMaskInverse(outMask);
    const hiIn = (inMask >> 4) & 0xf;
    const loIn = inMask & 0xf;
    const hiOut = (sboxOutMask >> 4) & 0xf;
    const loOut = sboxOutMask & 0xf;
    const hiCorr = correlationOf(lat, hiIn, hiOut);
    const loCorr = correlationOf(lat, loIn, loOut);
    const stepCorr = hiCorr * loCorr;
    correlation *= stepCorr;
    if (hiIn !== 0 || hiOut !== 0) activeSboxes++;
    if (loIn !== 0 || loOut !== 0) activeSboxes++;

    steps.push({
      round: d,
      inMask,
      sboxOutMask,
      outMask,
      correlation: stepCorr,
      bias: stepCorr / 2,
      nibbles: [
        { half: 'high', inMask: hiIn, outMask: hiOut, correlation: hiCorr, active: hiIn !== 0 || hiOut !== 0 },
        { half: 'low', inMask: loIn, outMask: loOut, correlation: loCorr, active: loIn !== 0 || loOut !== 0 },
      ],
    });
  }

  return {
    startMask: chain[0],
    endMask: chain[chain.length - 1],
    steps,
    correlation,
    bias: correlation / 2,
    activeSboxes,
  };
}

/**
 * The piling-up lemma in its original bias form:
 *   eps(X_1 XOR ... XOR X_n) = 2^(n-1) * PROD eps_i
 * Equivalent to multiplying correlations, and stated both ways in the UI
 * because the literature uses both.
 */
export function pilingUpBias(biases: readonly number[]): number {
  if (biases.length === 0) return 0.5;
  return Math.pow(2, biases.length - 1) * biases.reduce((acc, e) => acc * e, 1);
}

/**
 * The TRUE bias of the approximation <a,P> XOR <b,u_R> for one concrete key,
 * measured by running the real cipher on all 256 plaintexts. No sampling, no
 * estimate — for an 8-bit block the whole codebook is the population.
 */
export function exactBias(
  sbox: Sbox,
  key: SpnKey,
  cipherRounds: number,
  startMask: number,
  endMask: number,
): number {
  let matches = 0;
  for (let p = 0; p < 256; p++) {
    const u = lastRoundInput(p, key, sbox, cipherRounds);
    if (dot(startMask, p) === dot(endMask, u)) matches++;
  }
  return matches / 256 - 0.5;
}

/**
 * The same approximation measured across many keys. The piling-up lemma
 * predicts one number; reality gives a distribution, because the trails inside
 * the hull reinforce or cancel depending on the key. Showing the spread is the
 * honest version of "the bias is 1/8".
 */
export function biasAcrossKeys(
  sbox: Sbox,
  cipherRounds: number,
  startMask: number,
  endMask: number,
  masterKeys: readonly number[],
): number[] {
  return masterKeys.map((mk) => exactBias(sbox, generateKey(mk), cipherRounds, startMask, endMask));
}

/**
 * Evidence for one trail step: the parity relation checked against the real
 * S-box for every input, so the correlation is counted rather than claimed.
 */
export function verifyStep(
  sbox: Sbox,
  inMask: number,
  outMask: number,
): { matches: number; total: number; bias: number } {
  let matches = 0;
  for (let x = 0; x < 256; x++) {
    const y = ((sbox.table[(x >> 4) & 0xf] << 4) | sbox.table[x & 0xf]) & 0xff;
    if (dot(inMask, x) === dot(outMask, y)) matches++;
  }
  return { matches, total: 256, bias: matches / 256 - 0.5 };
}

/** Which nibble a mask lives in, or null if it straddles both. */
export function maskHalf(mask: number): NibbleHalf | null {
  const hi = (mask >> 4) & 0xf;
  const lo = mask & 0xf;
  if (hi !== 0 && lo !== 0) return null;
  return hi !== 0 ? 'high' : 'low';
}

/** Convenience for the attack panel: the nibble of u_R the end mask reads. */
export function endMaskNibble(endMask: number, half: NibbleHalf): number {
  return takeNibble(endMask, half);
}

export { permuteMask };
