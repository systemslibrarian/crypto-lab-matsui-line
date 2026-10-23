import { describe, expect, it } from 'vitest';
import { observeAdvanced } from './advanced.js';
import { exactBias } from './trail.js';
import { getSbox } from './sbox.js';
import { generateKey } from './spn.js';

describe('two-mask and zero-correlation extension', () => {
  it('keeps the complete joint distribution rather than assuming independence', () => {
    for (const count of [16, 64, 256] as const) {
      const result = observeAdvanced(0x1234, count);
      expect(result.jointCounts.reduce((sum, n) => sum + n, 0)).toBe(count);
      expect(result.relations[0].matches).toBe(result.jointCounts[2] + result.jointCounts[3]);
      expect(result.relations[1].matches).toBe(result.jointCounts[1] + result.jointCounts[3]);
      expect(result.relations[0].startMask).not.toBe(result.relations[1].startMask);
      expect(result.relations[0].endMask).not.toBe(result.relations[1].endMask);
    }
  });

  it('distinguishes a no-trail structural zero from finite-sample noise', () => {
    const sbox = getSbox('heys');
    for (let key = 0; key < 0x10000; key += 257) {
      const result = observeAdvanced(key, 256);
      expect(result.noNonzeroTrail).toBe(true);
      expect(result.structuralZero.matches).toBe(128);
      expect(exactBias(sbox, generateKey(key), 3, result.structuralZero.startMask, result.structuralZero.endMask))
        .toBe(0);
    }
    const shortCounts = [0x0000, 0x1234, 0xabcd].map((key) => observeAdvanced(key, 16).structuralZero.matches);
    expect(shortCounts.some((count) => count !== 8)).toBe(true);
  });

  it('rejects keys and sample counts outside the advanced controls', () => {
    expect(() => observeAdvanced(-1, 16)).toThrow('16-bit unsigned integer');
    expect(() => observeAdvanced(0x1_0000, 16)).toThrow('16-bit unsigned integer');
    expect(() => observeAdvanced(0x1234, 4096 as 16)).toThrow('samples must be 16, 64, or 256');
  });
});
