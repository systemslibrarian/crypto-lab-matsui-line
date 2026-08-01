/** Presentation helpers. No cryptography lives here. */

/** Width in hex digits also sets the mask: hex(k, 4) must not truncate a 16-bit key. */
export function hex(value: number, digits = 2): string {
  const mask = Math.pow(16, digits) - 1;
  return `0x${(value & mask).toString(16).toUpperCase().padStart(digits, '0')}`;
}

export function hexNibble(value: number): string {
  return `0x${(value & 0xf).toString(16).toUpperCase()}`;
}

/** 8-bit binary, split at the nibble boundary the S-box works on. */
export function bin8(value: number): string {
  const bits = (value & 0xff).toString(2).padStart(8, '0');
  return `${bits.slice(0, 4)} ${bits.slice(4)}`;
}

export function bin4(value: number): string {
  return (value & 0xf).toString(2).padStart(4, '0');
}

/** Signed decimal with a fixed sign column, e.g. "+0.1250" / "−0.0625". */
export function signed(value: number, digits = 4): string {
  if (Object.is(value, -0) || value === 0) return `${(0).toFixed(digits)}`;
  const sign = value > 0 ? '+' : '−';
  return `${sign}${Math.abs(value).toFixed(digits)}`;
}

function gcd(a: number, b: number): number {
  return b === 0 ? a : gcd(b, a % b);
}

/**
 * Biases here are always counts over 16 or 256 trials, so they have an exact
 * fractional form — and "1/8" reads far better than "0.1250" when the point is
 * that the number halves every round.
 */
export function asFraction(value: number, denominator = 256): string {
  if (value === 0) return '0';
  const sign = value < 0 ? '−' : '+';
  const numerator = Math.round(Math.abs(value) * denominator);
  if (numerator === 0) return '0';
  const divisor = gcd(numerator, denominator);
  const n = numerator / divisor;
  const d = denominator / divisor;
  return d === 1 ? `${sign}${n}` : `${sign}${n}/${d}`;
}

/** Same as asFraction, but for a magnitude — no sign column. */
export function magnitude(value: number, denominator = 256): string {
  const text = asFraction(Math.abs(value), denominator);
  return text.startsWith('+') ? text.slice(1) : text;
}

export function percent(value: number, digits = 1): string {
  return `${(value * 100).toFixed(digits)}%`;
}

/** "P3 ⊕ P0" — a mask written as the XOR of the bits it selects. */
export function maskTerms(mask: number, symbol: string, width: number): string {
  const terms: string[] = [];
  for (let i = width - 1; i >= 0; i--) {
    if ((mask >> i) & 1) terms.push(`${symbol}<sub>${i}</sub>`);
  }
  return terms.length === 0 ? '0' : terms.join(' ⊕ ');
}

/** Same, without markup, for aria-labels and plain-text contexts. */
export function maskTermsPlain(mask: number, symbol: string, width: number): string {
  const terms: string[] = [];
  for (let i = width - 1; i >= 0; i--) {
    if ((mask >> i) & 1) terms.push(`${symbol}${i}`);
  }
  return terms.length === 0 ? '0' : terms.join(' XOR ');
}

export function plural(count: number, one: string, many = `${one}s`): string {
  return count === 1 ? one : many;
}

/** Escape text destined for an innerHTML template. */
export function esc(text: string): string {
  return text.replace(/[&<>"']/g, (c) => {
    switch (c) {
      case '&':
        return '&amp;';
      case '<':
        return '&lt;';
      case '>':
        return '&gt;';
      case '"':
        return '&quot;';
      default:
        return '&#39;';
    }
  });
}
