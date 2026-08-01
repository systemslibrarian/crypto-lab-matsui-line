import { describe, expect, it } from 'vitest';
import {
  FULL_ROUNDS,
  decrypt,
  encrypt,
  generateKey,
  halfMask,
  lastRoundInput,
  peelLastRoundNibble,
  placeNibble,
  takeNibble,
  traceEncryption,
} from './spn.js';
import { getSbox, substitute, substituteInverse } from './sbox.js';
import { permute, permuteInverse } from './permutation.js';

const heys = getSbox('heys');
const present = getSbox('present');

/**
 * Cross-implementation vectors. These were produced by a literal transcription
 * of crypto-lab-biham-lens's own spn.ts/sbox.ts/permutation.ts, NOT by the code
 * under test. They are the guarantee that this lab attacks the same cipher the
 * differential lab attacks — if either repo's cipher drifts, this fails.
 */
const BIHAM_LENS_VECTORS = {
  heys: [
    { masterKey: 0x0000, subkeys: [0x00, 0x00, 0x00, 0x00, 0x00], ciphertexts: [0x8b, 0xa4, 0xa8, 0x0e, 0xc4, 0xc8, 0xe3, 0x2a] },
    { masterKey: 0x3a94, subkeys: [0x94, 0x43, 0x3a, 0xa9, 0x94], ciphertexts: [0xe6, 0x7a, 0xdd, 0xd1, 0x43, 0x7e, 0x78, 0x82] },
    { masterKey: 0x1234, subkeys: [0x34, 0x41, 0x12, 0x23, 0x34], ciphertexts: [0x0c, 0xde, 0x1a, 0x41, 0x2d, 0x2c, 0xd5, 0x70] },
    { masterKey: 0xbeef, subkeys: [0xef, 0xfb, 0xbe, 0xee, 0xef], ciphertexts: [0x9f, 0x14, 0x91, 0x9c, 0x39, 0x32, 0x54, 0x6d] },
    { masterKey: 0xace1, subkeys: [0xe1, 0x1a, 0xac, 0xce, 0xe1], ciphertexts: [0xed, 0x11, 0x33, 0x40, 0x44, 0xee, 0x6e, 0x92] },
    { masterKey: 0xffff, subkeys: [0xff, 0xff, 0xff, 0xff, 0xff], ciphertexts: [0xc2, 0x35, 0xc9, 0x2f, 0xda, 0xa9, 0xd9, 0x96] },
  ],
  present: [
    { masterKey: 0x0000, subkeys: [0x00, 0x00, 0x00, 0x00, 0x00], ciphertexts: [0x00, 0x9f, 0x9e, 0xc8, 0x5e, 0x34, 0x42, 0x2f] },
    { masterKey: 0x3a94, subkeys: [0x94, 0x43, 0x3a, 0xa9, 0x94], ciphertexts: [0xdc, 0xc7, 0x82, 0x3f, 0x8c, 0xec, 0xf1, 0x12] },
    { masterKey: 0x1234, subkeys: [0x34, 0x41, 0x12, 0x23, 0x34], ciphertexts: [0x08, 0x96, 0x34, 0x88, 0xf3, 0xc4, 0xe6, 0x3c] },
    { masterKey: 0xbeef, subkeys: [0xef, 0xfb, 0xbe, 0xee, 0xef], ciphertexts: [0x67, 0x84, 0x5a, 0x55, 0x46, 0x5e, 0x91, 0x31] },
    { masterKey: 0xace1, subkeys: [0xe1, 0x1a, 0xac, 0xce, 0xe1], ciphertexts: [0xd1, 0x5b, 0x81, 0x0b, 0x68, 0x07, 0xad, 0x77] },
    { masterKey: 0xffff, subkeys: [0xff, 0xff, 0xff, 0xff, 0xff], ciphertexts: [0x4f, 0xe9, 0x91, 0xcc, 0xf4, 0xcb, 0x46, 0x00] },
  ],
} as const;

const VECTOR_PLAINTEXTS = [0x00, 0x01, 0x2a, 0x7f, 0x80, 0xc3, 0xfe, 0xff];

describe('key schedule', () => {
  it('derives five 8-bit subkeys by rotating the master key left 4 bits', () => {
    for (const vector of BIHAM_LENS_VECTORS.heys) {
      expect(generateKey(vector.masterKey).subkeys).toEqual([...vector.subkeys]);
    }
  });

  it('masks the master key to 16 bits', () => {
    expect(generateKey(0x1_3a94).masterKey).toBe(0x3a94);
  });
});

describe('known-answer tests against crypto-lab-biham-lens', () => {
  for (const [name, sbox] of [
    ['heys', heys],
    ['present', present],
  ] as const) {
    it(`reproduces the differential lab's ciphertexts — ${name} S-box (${BIHAM_LENS_VECTORS[name].length * VECTOR_PLAINTEXTS.length} vectors)`, () => {
      for (const vector of BIHAM_LENS_VECTORS[name]) {
        const key = generateKey(vector.masterKey);
        const actual = VECTOR_PLAINTEXTS.map((p) => encrypt(p, key, sbox));
        expect(actual).toEqual([...vector.ciphertexts]);
      }
    });
  }
});

describe('encrypt / decrypt', () => {
  it('round-trips every plaintext under every round count and both S-boxes', () => {
    for (const sbox of [heys, present]) {
      for (let rounds = 2; rounds <= FULL_ROUNDS; rounds++) {
        for (const masterKey of [0x0000, 0x3a94, 0xbeef, 0xffff]) {
          const key = generateKey(masterKey);
          for (let p = 0; p < 256; p++) {
            expect(decrypt(encrypt(p, key, sbox, rounds), key, sbox, rounds)).toBe(p);
          }
        }
      }
    }
  });

  it('is a permutation of the block space for every key', () => {
    for (const masterKey of [0x0000, 0x3a94, 0x1234, 0xace1]) {
      const key = generateKey(masterKey);
      const seen = new Set<number>();
      for (let p = 0; p < 256; p++) seen.add(encrypt(p, key, heys));
      expect(seen.size).toBe(256);
    }
  });

  it('rejects round counts outside 2..4', () => {
    const key = generateKey(0x3a94);
    expect(() => encrypt(0, key, heys, 1)).toThrow(RangeError);
    expect(() => encrypt(0, key, heys, 5)).toThrow(RangeError);
    expect(() => encrypt(0, key, heys, 2.5)).toThrow(RangeError);
  });
});

describe('lastRoundInput', () => {
  it('is exactly what one inverse substitution and the final key XOR recover', () => {
    for (const sbox of [heys, present]) {
      for (let rounds = 2; rounds <= FULL_ROUNDS; rounds++) {
        const key = generateKey(0x3a94);
        for (let p = 0; p < 256; p++) {
          const c = encrypt(p, key, sbox, rounds);
          const peeled = substituteInverse((c ^ key.subkeys[rounds]) & 0xff, sbox);
          expect(peeled).toBe(lastRoundInput(p, key, sbox, rounds));
        }
      }
    }
  });

  it('agrees with the trace stage marked as the attack target', () => {
    const key = generateKey(0xbeef);
    for (let p = 0; p < 256; p++) {
      const target = traceEncryption(p, key, heys, 3).find((s) => s.isTargetState);
      expect(target?.state).toBe(lastRoundInput(p, key, heys, 3));
    }
  });
});

describe('peelLastRoundNibble', () => {
  it('recovers the true nibble exactly when the guess is the true subkey nibble', () => {
    const key = generateKey(0xace1);
    const rounds = 3;
    for (const half of ['low', 'high'] as const) {
      const trueGuess = takeNibble(key.subkeys[rounds], half);
      for (let p = 0; p < 256; p++) {
        const c = encrypt(p, key, heys, rounds);
        const expected = takeNibble(lastRoundInput(p, key, heys, rounds), half);
        expect(peelLastRoundNibble(c, trueGuess, half, heys)).toBe(expected);
      }
    }
  });

  it('produces something else for at least one pair under every wrong guess', () => {
    const key = generateKey(0xace1);
    const rounds = 3;
    const trueGuess = takeNibble(key.subkeys[rounds], 'high');
    for (let guess = 0; guess < 16; guess++) {
      if (guess === trueGuess) continue;
      const wrong = [...Array(256).keys()].some((p) => {
        const c = encrypt(p, key, heys, rounds);
        return peelLastRoundNibble(c, guess, 'high', heys) !== takeNibble(lastRoundInput(p, key, heys, rounds), 'high');
      });
      expect(wrong).toBe(true);
    }
  });
});

describe('nibble helpers', () => {
  it('take / place / mask agree with each other', () => {
    for (let byte = 0; byte < 256; byte++) {
      expect(placeNibble(takeNibble(byte, 'low'), 'low')).toBe(byte & 0x0f);
      expect(placeNibble(takeNibble(byte, 'high'), 'high')).toBe(byte & 0xf0);
    }
    expect(halfMask('low')).toBe(0x0f);
    expect(halfMask('high')).toBe(0xf0);
  });
});

describe('building blocks', () => {
  it('substitute and its inverse cancel', () => {
    for (const sbox of [heys, present]) {
      for (let b = 0; b < 256; b++) expect(substituteInverse(substitute(b, sbox), sbox)).toBe(b);
    }
  });

  it('permute and its inverse cancel, and the permutation is a bijection', () => {
    const seen = new Set<number>();
    for (let b = 0; b < 256; b++) {
      expect(permuteInverse(permute(b))).toBe(b);
      seen.add(permute(b));
    }
    expect(seen.size).toBe(256);
  });

  it('drops the permutation in the final round only', () => {
    // With a zero key the 2-round cipher is S(P(S(p))) and nothing else.
    const key = generateKey(0x0000);
    for (let p = 0; p < 256; p++) {
      expect(encrypt(p, key, heys, 2)).toBe(substitute(permute(substitute(p, heys)), heys));
    }
  });
});
