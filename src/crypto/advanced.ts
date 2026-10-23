/** Two-mask and structural-zero observations on the real, deliberately tiny SPN. */
import { dot, getSbox } from './sbox.js';
import { generateKey, lastRoundInput } from './spn.js';
import { deadApproximation, rankApproximations, trailBetween } from './trail.js';

export interface RelationCount {
  readonly startMask: number;
  readonly endMask: number;
  readonly matches: number;
}

export interface AdvancedObservation {
  readonly samples: number;
  readonly key: number;
  readonly relations: readonly [RelationCount, RelationCount];
  /** Index = (relation A holds ? 2 : 0) + (relation B holds ? 1 : 0). */
  readonly jointCounts: readonly [number, number, number, number];
  readonly structuralZero: RelationCount;
  readonly noNonzeroTrail: boolean;
}

const heys = getSbox('heys');
const innerRounds = 2;
const cipherRounds = 3;

/**
 * A zero with no nonzero trail holds for every round key; a sampled zero can
 * also happen by chance. Two separately selected relations retain their joint
 * four-cell distribution rather than silently treating their counts as independent.
 */
export function observeAdvanced(masterKey: number, samples: 16 | 64 | 256): AdvancedObservation {
  const ranked = rankApproximations(heys, innerRounds, { endHalf: 'high' });
  const first = ranked[0];
  const second = ranked.find(
    (candidate) => candidate.startMask !== first.startMask && candidate.endMask !== first.endMask,
  );
  const dead = deadApproximation(heys, innerRounds, 'high');
  if (!second || !dead) throw new Error('The selected toy cipher lacks the required mask examples.');

  const key = generateKey(masterKey);
  const joint = [0, 0, 0, 0];
  const matches = [0, 0, 0];
  const pairs = [first, second, dead];
  for (let i = 0; i < samples; i++) {
    // 73 is odd, so this visits each of the 256 plaintexts once. The short
    // prefixes are a deterministic sample, not the complete population.
    const plaintext = (i * 73 + 19) & 255;
    const lastInput = lastRoundInput(plaintext, key, heys, cipherRounds);
    const holds = pairs.map(
      ({ startMask, endMask }) => dot(startMask, plaintext) === dot(endMask, lastInput),
    );
    for (let j = 0; j < matches.length; j++) if (holds[j]) matches[j]++;
    joint[(holds[0] ? 2 : 0) + (holds[1] ? 1 : 0)]++;
  }
  return {
    samples,
    key: masterKey & 0xffff,
    relations: [
      { startMask: first.startMask, endMask: first.endMask, matches: matches[0] },
      { startMask: second.startMask, endMask: second.endMask, matches: matches[1] },
    ],
    jointCounts: joint as [number, number, number, number],
    structuralZero: { startMask: dead.startMask, endMask: dead.endMask, matches: matches[2] },
    noNonzeroTrail: trailBetween(heys, innerRounds, dead.startMask, dead.endMask) === null,
  };
}
