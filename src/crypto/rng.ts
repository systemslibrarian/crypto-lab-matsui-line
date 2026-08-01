/**
 * A small deterministic PRNG (mulberry32) used ONLY to draw which plaintexts
 * the attacker happens to observe, so that a run is reproducible from its seed
 * and you can re-run the same experiment after changing one knob.
 *
 * This is NOT a cryptographic RNG and is never used for key material: keys
 * come from crypto.getRandomValues() in spn.ts. Making the *attacker's data*
 * reproducible is a teaching decision, not a cryptographic one.
 */

export interface Rng {
  /** Uniform float in [0, 1). */
  next(): number;
  /** Uniform integer in [0, 256). */
  nextByte(): number;
}

export function mulberry32(seed: number): Rng {
  let a = seed >>> 0;
  const next = (): number => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  return { next, nextByte: () => Math.floor(next() * 256) & 0xff };
}

/** A fresh seed from the platform CSPRNG, so each session's data differs. */
export function randomSeed(): number {
  const buf = new Uint32Array(1);
  crypto.getRandomValues(buf);
  return buf[0] >>> 0;
}
