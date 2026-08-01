/**
 * The toy SPN (substitution-permutation network) under attack.
 *
 * Identical to the cipher in crypto-lab-biham-lens — same S-box, same bit
 * permutation, same key schedule, same round structure — so the differential
 * lab and this linear lab attack the same target.
 *
 *   8-bit block, 16-bit master key, R rounds (R = 4 is the full cipher):
 *
 *     state = plaintext
 *     for r in 0 .. R-1:
 *         state = S( state XOR K_r )        // key mixing, then substitution
 *         if r < R-1: state = P( state )    // no permutation in the last round
 *     ciphertext = state XOR K_R            // final key mixing
 *
 * The permutation is dropped in the last round (as in DES and every textbook
 * SPN) because a permutation after the final substitution would be public and
 * invertible, so it adds nothing.
 *
 * NOT PRODUCTION CRYPTOGRAPHY. An 8-bit block has 256 plaintexts; the whole
 * codebook fits in a browser tab. It is built to be broken in front of you.
 */

import { substitute, substituteInverse, type Sbox } from './sbox.js';
import { permute, permuteInverse } from './permutation.js';

/** The full cipher. Reduced-round variants (3, 2) exist for the attack panel. */
export const FULL_ROUNDS = 4;
export const MIN_ROUNDS = 2;

export interface SpnKey {
  /** 16-bit master key. */
  readonly masterKey: number;
  /** Five 8-bit subkeys: one per round plus the final mixing key. */
  readonly subkeys: readonly number[];
}

/**
 * Key schedule: take the low byte, rotate the 16-bit master key left by 4 bits,
 * repeat. Weak on purpose — a real schedule would destroy the relationship
 * between subkeys, and the point here is the *attack*, not the schedule.
 */
export function generateKey(masterKey: number): SpnKey {
  const subkeys: number[] = [];
  let key = masterKey & 0xffff;
  for (let i = 0; i < 5; i++) {
    subkeys.push(key & 0xff);
    key = ((key << 4) | (key >> 12)) & 0xffff;
  }
  return { masterKey: masterKey & 0xffff, subkeys };
}

/** A fresh key from the platform CSPRNG. Never persisted; per-session only. */
export function randomKey(): SpnKey {
  const buf = new Uint8Array(2);
  crypto.getRandomValues(buf);
  return generateKey((buf[0] << 8) | buf[1]);
}

function assertRounds(rounds: number): void {
  if (!Number.isInteger(rounds) || rounds < MIN_ROUNDS || rounds > FULL_ROUNDS) {
    throw new RangeError(`rounds must be an integer in ${MIN_ROUNDS}..${FULL_ROUNDS}, got ${rounds}`);
  }
}

export function encrypt(plaintext: number, key: SpnKey, sbox: Sbox, rounds: number = FULL_ROUNDS): number {
  assertRounds(rounds);
  let state = plaintext & 0xff;
  for (let r = 0; r < rounds; r++) {
    state = substitute(state ^ key.subkeys[r], sbox);
    if (r < rounds - 1) state = permute(state);
  }
  return (state ^ key.subkeys[rounds]) & 0xff;
}

export function decrypt(ciphertext: number, key: SpnKey, sbox: Sbox, rounds: number = FULL_ROUNDS): number {
  assertRounds(rounds);
  let state = (ciphertext ^ key.subkeys[rounds]) & 0xff;
  for (let r = rounds - 1; r >= 0; r--) {
    if (r < rounds - 1) state = permuteInverse(state);
    state = substituteInverse(state, sbox) ^ key.subkeys[r];
  }
  return state & 0xff;
}

/**
 * The state that goes *into* the last round's S-box — the quantity a linear
 * approximation targets. Matsui's Algorithm 2 works by guessing the final
 * subkey, peeling the last substitution off the ciphertext to recover this
 * value, and checking which guess makes the approximation hold most often.
 */
export function lastRoundInput(plaintext: number, key: SpnKey, sbox: Sbox, rounds: number = FULL_ROUNDS): number {
  assertRounds(rounds);
  let state = plaintext & 0xff;
  for (let r = 0; r < rounds - 1; r++) {
    state = permute(substitute(state ^ key.subkeys[r], sbox));
  }
  return (state ^ key.subkeys[rounds - 1]) & 0xff;
}

/**
 * Peel the last round off a ciphertext under a *guessed* nibble of the final
 * subkey, returning that nibble of the last round's S-box input.
 *
 * Because the S-box is applied to each nibble independently, a guess at one
 * nibble of K_R is enough to undo one nibble of the last substitution — which
 * is why the attack costs 16 guesses and not 256.
 */
export function peelLastRoundNibble(
  ciphertext: number,
  guess: number,
  half: NibbleHalf,
  sbox: Sbox,
): number {
  const cn = half === 'low' ? ciphertext & 0xf : (ciphertext >> 4) & 0xf;
  return sbox.inverse[(cn ^ guess) & 0xf];
}

export type NibbleHalf = 'low' | 'high';

/** Position of a nibble inside the byte, as a mask. */
export function halfMask(half: NibbleHalf): number {
  return half === 'low' ? 0x0f : 0xf0;
}

/** Lift a nibble value into its position in the byte. */
export function placeNibble(nibble: number, half: NibbleHalf): number {
  return half === 'low' ? nibble & 0xf : (nibble & 0xf) << 4;
}

/** Extract a nibble from a byte. */
export function takeNibble(byte: number, half: NibbleHalf): number {
  return half === 'low' ? byte & 0xf : (byte >> 4) & 0xf;
}

export type StageKind = 'input' | 'xor-key' | 'sbox' | 'permute' | 'output';

export interface TraceStage {
  readonly kind: StageKind;
  readonly label: string;
  readonly round: number;
  readonly state: number;
  /** True when this stage is the input to the final S-box the attack targets. */
  readonly isTargetState?: boolean;
}

/** Every observable state of one encryption, for the cipher walkthrough. */
export function traceEncryption(
  plaintext: number,
  key: SpnKey,
  sbox: Sbox,
  rounds: number = FULL_ROUNDS,
): TraceStage[] {
  assertRounds(rounds);
  const stages: TraceStage[] = [];
  let state = plaintext & 0xff;
  stages.push({ kind: 'input', label: 'Plaintext', round: 0, state });

  for (let r = 0; r < rounds; r++) {
    state = (state ^ key.subkeys[r]) & 0xff;
    stages.push({
      kind: 'xor-key',
      label: `Round ${r + 1}: XOR K${r + 1}`,
      round: r + 1,
      state,
      isTargetState: r === rounds - 1,
    });
    state = substitute(state, sbox);
    stages.push({ kind: 'sbox', label: `Round ${r + 1}: S-box`, round: r + 1, state });
    if (r < rounds - 1) {
      state = permute(state);
      stages.push({ kind: 'permute', label: `Round ${r + 1}: Permute`, round: r + 1, state });
    }
  }

  state = (state ^ key.subkeys[rounds]) & 0xff;
  stages.push({ kind: 'output', label: `Final: XOR K${rounds + 1}`, round: rounds + 1, state });
  return stages;
}
