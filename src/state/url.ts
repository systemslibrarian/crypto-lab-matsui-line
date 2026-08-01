/**
 * Experiment state in the URL.
 *
 * A surprising result is only useful if someone else can reproduce it, so
 * everything that determines an outcome — cipher, target, traffic, masks, the
 * key, and the sampling seed — round-trips through the query string. Sharing a
 * link shares the exact experiment, not a description of one.
 *
 * The key travels in the URL by design: this is a toy cipher and the link is an
 * explicit share, so pinning the key is what makes the ranking reproducible.
 */

import type { SboxName } from '../crypto/sbox.js';
import type { NibbleHalf } from '../crypto/spn.js';

export type ApproxMode = 'auto' | 'ranked' | 'custom';
/** Traffic is either a sample count or the whole 256-plaintext codebook. */
export type Traffic = number | 'codebook';

export interface ExperimentState {
  sboxName: SboxName;
  cipherRounds: number;
  half: NibbleHalf;
  traffic: Traffic;
  approxMode: ApproxMode;
  customStart: number;
  customEnd: number;
  masterKey: number;
  /** Seed for the known-plaintext draw; null means "fresh randomness each run". */
  seed: number | null;
}

const SBOXES: readonly SboxName[] = ['heys', 'present'];
const HALVES: readonly NibbleHalf[] = ['low', 'high'];
const MODES: readonly ApproxMode[] = ['auto', 'ranked', 'custom'];
export const TRAFFIC_CHOICES: readonly Traffic[] = [16, 64, 256, 1024, 4096, 'codebook'];

function clampByte(value: number, fallback: number): number {
  return Number.isFinite(value) ? Math.max(0, Math.min(255, Math.trunc(value))) : fallback;
}

export function parseState(search: string, defaults: ExperimentState): ExperimentState {
  const params = new URLSearchParams(search);
  const state: ExperimentState = { ...defaults };

  const sbox = params.get('sbox');
  if (sbox && (SBOXES as readonly string[]).includes(sbox)) state.sboxName = sbox as SboxName;

  const rounds = Number(params.get('rounds'));
  if (rounds >= 2 && rounds <= 4) state.cipherRounds = Math.trunc(rounds);

  const half = params.get('half');
  if (half && (HALVES as readonly string[]).includes(half)) state.half = half as NibbleHalf;

  const traffic = params.get('n');
  if (traffic === 'codebook') state.traffic = 'codebook';
  else if (traffic !== null) {
    const n = Number(traffic);
    if (Number.isFinite(n) && n >= 1 && n <= 1 << 20) state.traffic = Math.trunc(n);
  }

  const approx = params.get('approx');
  if (approx && (MODES as readonly string[]).includes(approx)) state.approxMode = approx as ApproxMode;

  if (params.has('a')) state.customStart = clampByte(Number(params.get('a')), defaults.customStart);
  if (params.has('b')) state.customEnd = clampByte(Number(params.get('b')), defaults.customEnd);

  if (params.has('k')) {
    const k = Number(params.get('k'));
    if (Number.isFinite(k)) state.masterKey = Math.trunc(k) & 0xffff;
  }

  if (params.has('seed')) {
    const seed = Number(params.get('seed'));
    if (Number.isFinite(seed)) state.seed = Math.trunc(seed) >>> 0;
  }

  return state;
}

/** The query string for a state, omitting nothing that affects a result. */
export function toSearch(state: ExperimentState): string {
  const params = new URLSearchParams();
  params.set('sbox', state.sboxName);
  params.set('rounds', String(state.cipherRounds));
  params.set('half', state.half);
  params.set('n', state.traffic === 'codebook' ? 'codebook' : String(state.traffic));
  params.set('approx', state.approxMode);
  if (state.approxMode === 'custom') {
    params.set('a', String(state.customStart));
    params.set('b', String(state.customEnd));
  }
  params.set('k', String(state.masterKey));
  if (state.seed !== null) params.set('seed', String(state.seed));
  return `?${params.toString()}`;
}

export function shareUrl(state: ExperimentState, href: string): string {
  const url = new URL(href);
  url.search = toSearch(state);
  url.hash = '#attack';
  return url.toString();
}
