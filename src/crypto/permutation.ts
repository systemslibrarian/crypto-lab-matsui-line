/**
 * The toy SPN's bit permutation — identical to crypto-lab-biham-lens.
 *
 * PERMUTATION[i] = j means input bit i is written to output position j.
 * Bit positions [7,6,5,4,3,2,1,0] -> [7,3,6,2,5,1,4,0].
 *
 * The permutation is what carries a one-nibble S-box leak into *both* nibbles
 * of the next round — which is exactly why a multi-round linear approximation
 * has to keep paying the piling-up tax.
 */

const PERMUTATION: readonly number[] = [7, 3, 6, 2, 5, 1, 4, 0];

function computeInverse(perm: readonly number[]): readonly number[] {
  const inverse = new Array<number>(perm.length).fill(0);
  for (let i = 0; i < perm.length; i++) inverse[perm[i]] = i;
  return inverse;
}

const PERMUTATION_INV: readonly number[] = computeInverse(PERMUTATION);

export function permute(byte: number): number {
  let result = 0;
  for (let i = 0; i < 8; i++) {
    result |= ((byte >> i) & 1) << PERMUTATION[i];
  }
  return result & 0xff;
}

export function permuteInverse(byte: number): number {
  let result = 0;
  for (let i = 0; i < 8; i++) {
    result |= ((byte >> i) & 1) << PERMUTATION_INV[i];
  }
  return result & 0xff;
}

/**
 * A linear *mask* travels through a bit permutation exactly like a value does:
 * if w = permute(v) then <gamma, v> = <permute(gamma), w>, because the
 * permutation only relabels bit positions. This one-line fact is what lets a
 * trail be tracked as a sequence of masks.
 */
export const permuteMask = permute;
export const permuteMaskInverse = permuteInverse;

export function getPermutation(): readonly number[] {
  return PERMUTATION;
}

export function getPermutationInverse(): readonly number[] {
  return PERMUTATION_INV;
}
