import { describe, expect, it } from 'vitest';
import { SBOXES, dot, getSbox, substitute, substituteInverse } from './sbox.js';

describe('S-box tables', () => {
  it('match the published tables', () => {
    // Heys' tutorial S-box (also Stinson, 3rd ed.).
    expect([...SBOXES.heys.table]).toEqual([
      0xe, 0x4, 0xd, 0x1, 0x2, 0xf, 0xb, 0x8, 0x3, 0xa, 0x6, 0xc, 0x5, 0x9, 0x0, 0x7,
    ]);
    // PRESENT, Bogdanov et al., CHES 2007, Table 1.
    expect([...SBOXES.present.table]).toEqual([
      0xc, 0x5, 0x6, 0xb, 0x9, 0x0, 0xa, 0xd, 0x3, 0xe, 0xf, 0x8, 0x4, 0x7, 0x1, 0x2,
    ]);
  });

  it('are bijections on the nibble, with correct inverse tables', () => {
    for (const name of ['heys', 'present'] as const) {
      const sbox = getSbox(name);
      expect(new Set(sbox.table).size).toBe(16);
      for (let x = 0; x < 16; x++) {
        expect(sbox.inverse[sbox.table[x]]).toBe(x);
        expect(sbox.table[sbox.inverse[x]]).toBe(x);
      }
    }
  });

  it('apply to both nibbles independently and invert cleanly', () => {
    for (const name of ['heys', 'present'] as const) {
      const sbox = getSbox(name);
      for (let byte = 0; byte < 256; byte++) {
        const out = substitute(byte, sbox);
        expect((out >> 4) & 0xf).toBe(sbox.table[(byte >> 4) & 0xf]);
        expect(out & 0xf).toBe(sbox.table[byte & 0xf]);
        expect(substituteInverse(out, sbox)).toBe(byte);
      }
    }
  });
});

describe('dot — the masked parity <a, x>', () => {
  it('is the XOR of the selected bits', () => {
    expect(dot(0b1111, 0b1010)).toBe(0);
    expect(dot(0b1111, 0b1110)).toBe(1);
    expect(dot(0b0001, 0b0001)).toBe(1);
    expect(dot(0, 0xff)).toBe(0);
    expect(dot(0xff, 0)).toBe(0);
  });

  it('is linear in its second argument — the property the whole attack rests on', () => {
    for (let mask = 0; mask < 256; mask += 3) {
      for (let x = 0; x < 256; x += 5) {
        for (let y = 0; y < 256; y += 7) {
          expect(dot(mask, x ^ y)).toBe(dot(mask, x) ^ dot(mask, y));
        }
      }
    }
  });

  it('makes a round-key XOR flip the sign of an approximation, never its strength', () => {
    // <b, u XOR k> = <b, u> XOR <b, k>: a constant. This is why key material
    // cannot defend against a linear approximation.
    for (let mask = 1; mask < 256; mask += 11) {
      for (let key = 0; key < 256; key += 13) {
        const constant = dot(mask, key);
        for (let u = 0; u < 256; u += 17) {
          expect(dot(mask, u ^ key)).toBe(dot(mask, u) ^ constant);
        }
      }
    }
  });
});
