import { describe, expect, it } from 'vitest';
import { parseState, toSearch, TRAFFIC_CHOICES, type ExperimentState } from './url.js';

const defaults: ExperimentState = {
  sboxName: 'heys',
  cipherRounds: 3,
  half: 'high',
  traffic: 256,
  approxMode: 'auto',
  customStart: 9,
  customEnd: 192,
  masterKey: 0x3a94,
  seed: 3198,
};

describe('experiment URL state', () => {
  it('round-trips every traffic choice exposed by the controls', () => {
    for (const traffic of TRAFFIC_CHOICES) {
      const state = { ...defaults, traffic };
      expect(parseState(toSearch(state), defaults)).toEqual(state);
    }
  });

  it('rejects traffic values outside the bounded controls', () => {
    for (const value of ['0', '17', '64.5', '4097', '1048576', 'Infinity', 'NaN']) {
      expect(parseState(`?n=${value}`, defaults).traffic).toBe(defaults.traffic);
    }
  });
});
