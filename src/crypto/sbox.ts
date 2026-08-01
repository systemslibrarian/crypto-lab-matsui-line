/**
 * 4-bit S-boxes for the toy SPN.
 *
 * These are the *same two S-boxes* used by crypto-lab-biham-lens, so the
 * cipher attacked here is bit-for-bit the cipher attacked there. That is
 * deliberate: differential (Biham Lens) and linear (this lab) cryptanalysis
 * are the pair-mate attacks, and comparing them only means something if they
 * are aimed at the same target.
 *
 *   - 'heys'    — the textbook toy S-box (Heys' tutorial / Stinson 3rd ed).
 *   - 'present' — the PRESENT S-box (Bogdanov et al., CHES 2007).
 *
 * Nothing here is production cryptography. A 4-bit S-box over an 8-bit block
 * exists so the attack is *visible*, not so the cipher is strong.
 */

export type SboxName = 'heys' | 'present';

export interface Sbox {
  readonly name: SboxName;
  /** Human label used in the UI. */
  readonly label: string;
  /** Forward table: table[x] = S(x), x and S(x) both 4-bit. */
  readonly table: readonly number[];
  /** Inverse table: inverse[S(x)] = x. */
  readonly inverse: readonly number[];
  /** One-line note on what this S-box was chosen for. */
  readonly note: string;
}

const HEYS_TABLE: readonly number[] = [
  0xe, 0x4, 0xd, 0x1, 0x2, 0xf, 0xb, 0x8, 0x3, 0xa, 0x6, 0xc, 0x5, 0x9, 0x0, 0x7,
];

const PRESENT_TABLE: readonly number[] = [
  0xc, 0x5, 0x6, 0xb, 0x9, 0x0, 0xa, 0xd, 0x3, 0xe, 0xf, 0x8, 0x4, 0x7, 0x1, 0x2,
];

function invert(table: readonly number[]): readonly number[] {
  const inverse = new Array<number>(16).fill(0);
  for (let x = 0; x < 16; x++) inverse[table[x]] = x;
  return inverse;
}

export const SBOXES: Readonly<Record<SboxName, Sbox>> = {
  heys: {
    name: 'heys',
    label: 'Heys (textbook toy)',
    table: HEYS_TABLE,
    inverse: invert(HEYS_TABLE),
    note: 'The tutorial S-box. Its best linear approximation is biased by 6/16 — a large leak.',
  },
  present: {
    name: 'present',
    label: 'PRESENT (Bogdanov 2007)',
    table: PRESENT_TABLE,
    inverse: invert(PRESENT_TABLE),
    note: 'A real lightweight-cipher S-box, chosen so no linear approximation is biased by more than 4/16.',
  },
};

export function getSbox(name: SboxName): Sbox {
  return SBOXES[name];
}

/** Apply the S-box to both nibbles of a byte. */
export function substitute(byte: number, sbox: Sbox): number {
  const hi = (byte >> 4) & 0xf;
  const lo = byte & 0xf;
  return ((sbox.table[hi] << 4) | sbox.table[lo]) & 0xff;
}

/** Undo the S-box on both nibbles of a byte. */
export function substituteInverse(byte: number, sbox: Sbox): number {
  const hi = (byte >> 4) & 0xf;
  const lo = byte & 0xf;
  return ((sbox.inverse[hi] << 4) | sbox.inverse[lo]) & 0xff;
}

/**
 * Parity of a masked value — the `<a, x>` of linear cryptanalysis, i.e. the
 * XOR of the bits of x selected by the mask a. Every linear approximation in
 * this lab is a statement about two of these parities being equal.
 */
export function dot(mask: number, value: number): number {
  let v = mask & value;
  v ^= v >> 4;
  v ^= v >> 2;
  v ^= v >> 1;
  return v & 1;
}
