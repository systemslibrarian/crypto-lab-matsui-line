import { describe, expect, it } from 'vitest';
import {
  asFraction,
  bin4,
  bin8,
  esc,
  hex,
  hexNibble,
  magnitude,
  maskTerms,
  maskTermsPlain,
  percent,
  plural,
  signed,
} from './format.js';

describe('number formatting', () => {
  it('renders bytes as hex and nibble-split binary', () => {
    expect(hex(0x2a)).toBe('0x2A');
    expect(hex(0x07)).toBe('0x07');
    // The width sets the mask too — a 16-bit key must not print as its low byte.
    expect(hex(0x3a94, 4)).toBe('0x3A94');
    expect(hex(0x13a94, 4)).toBe('0x3A94');
    expect(hex(0x3a94)).toBe('0x94');
    expect(bin8(0b1010_0101)).toBe('1010 0101');
    expect(bin8(3)).toBe('0000 0011');
    expect(bin4(0b1011)).toBe('1011');
    expect(hexNibble(12)).toBe('0xC');
  });

  it('keeps a sign column so numbers line up in a table', () => {
    expect(signed(0.125)).toBe('+0.1250');
    expect(signed(-0.125)).toBe('−0.1250');
    expect(signed(0)).toBe('0.0000');
    expect(signed(-0)).toBe('0.0000');
    expect(signed(0.5, 2)).toBe('+0.50');
  });

  it('recovers the exact fraction behind a counted bias', () => {
    // Every bias in this lab is a count over 16 or 256, so it has an exact
    // fractional form — and "1/8" teaches better than "0.1250".
    expect(asFraction(0.125, 256)).toBe('+1/8');
    expect(asFraction(-0.25, 16)).toBe('−1/4');
    expect(asFraction(6 / 16, 16)).toBe('+3/8');
    expect(asFraction(0)).toBe('0');
    expect(asFraction(0.5, 16)).toBe('+1/2');
    expect(asFraction(-1 / 32, 4096)).toBe('−1/32');
    expect(magnitude(-1 / 8, 256)).toBe('1/8');
    expect(magnitude(0.375, 16)).toBe('3/8');
  });

  it('rounds a bias too small for its denominator down to zero rather than lying', () => {
    expect(asFraction(0.0001, 16)).toBe('0');
  });

  it('formats percentages', () => {
    expect(percent(0.977)).toBe('97.7%');
    expect(percent(1, 0)).toBe('100%');
  });

  it('pluralises', () => {
    expect(plural(1, 'plaintext')).toBe('plaintext');
    expect(plural(2, 'plaintext')).toBe('plaintexts');
    expect(plural(2, 'index', 'indices')).toBe('indices');
  });
});

describe('mask rendering', () => {
  it('writes a mask as the XOR of the bits it selects, most significant first', () => {
    expect(maskTermsPlain(0b1001, 'X', 4)).toBe('X3 XOR X0');
    expect(maskTermsPlain(0b1100_0000, 'U', 8)).toBe('U7 XOR U6');
    expect(maskTermsPlain(0, 'X', 4)).toBe('0');
    expect(maskTerms(0b0100, 'Y', 4)).toBe('Y<sub>2</sub>');
    expect(maskTerms(0b1001, 'X', 4)).toBe('X<sub>3</sub> ⊕ X<sub>0</sub>');
  });

  it('only reads bits inside the requested width', () => {
    expect(maskTermsPlain(0b1111_0000, 'X', 4)).toBe('0');
  });
});

describe('escaping', () => {
  it('neutralises markup before it reaches innerHTML', () => {
    expect(esc('<script>alert("x")</script>')).toBe(
      '&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;',
    );
    expect(esc("it's & fine")).toBe('it&#39;s &amp; fine');
  });
});
