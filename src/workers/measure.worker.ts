/**
 * The success-rate measurement runs hundreds of complete attacks. Doing that on
 * the main thread froze the page on slower machines and — worse for a teaching
 * demo — made a genuine measurement indistinguishable from a stalled one. Here
 * it runs off-thread and reports real progress, so the count you watch is the
 * count being performed.
 */

import { measureSuccessRate, type SuccessPoint } from '../crypto/attack.js';
import { getSbox, type SboxName } from '../crypto/sbox.js';
import type { NibbleHalf } from '../crypto/spn.js';

export interface MeasureRequest {
  readonly sboxName: SboxName;
  readonly cipherRounds: number;
  readonly half: NibbleHalf;
  readonly startMask: number;
  readonly endMask: number;
  readonly sampleCounts: number[];
  readonly keyCount: number;
  readonly bias: number;
  readonly seed: number;
  readonly comparison?: boolean;
}

export type MeasureMessage =
  | { readonly kind: 'progress'; readonly completed: number; readonly total: number }
  | { readonly kind: 'done'; readonly points: SuccessPoint[]; readonly seed: number }
  | { readonly kind: 'comparison'; readonly repeated: SuccessPoint[]; readonly distinct: SuccessPoint[]; readonly seed: number }
  | { readonly kind: 'error'; readonly message: string };

self.onmessage = (event: MessageEvent<MeasureRequest>) => {
  const request = event.data;
  try {
    let lastPost = 0;
    const base = {
      sbox: getSbox(request.sboxName),
      cipherRounds: request.cipherRounds,
      half: request.half,
      startMask: request.startMask,
      endMask: request.endMask,
      sampleCounts: request.sampleCounts,
      keyCount: request.keyCount,
      bias: request.bias,
      seed: request.seed,
    };
    const perMode = request.sampleCounts.length * request.keyCount;
    const reportProgress = (offset: number) => (completed: number, total: number): void => {
        // Post at most every 8 attacks: enough to look live, few enough that
        // messaging does not become the bottleneck it is reporting on.
        const globalCompleted = offset + completed;
        const globalTotal = request.comparison ? total * 2 : total;
        if (completed === total || globalCompleted - lastPost >= 8) {
          lastPost = globalCompleted;
          const message: MeasureMessage = { kind: 'progress', completed: globalCompleted, total: globalTotal };
          self.postMessage(message);
        }
    };
    const repeated = measureSuccessRate({ ...base, sampling: 'repeated', onProgress: reportProgress(0) });
    const message: MeasureMessage = request.comparison
      ? {
          kind: 'comparison',
          repeated,
          distinct: measureSuccessRate({ ...base, sampling: 'distinct', onProgress: reportProgress(perMode) }),
          seed: request.seed,
        }
      : { kind: 'done', points: repeated, seed: request.seed };
    self.postMessage(message);
  } catch (error) {
    const message: MeasureMessage = {
      kind: 'error',
      message: error instanceof Error ? error.message : String(error),
    };
    self.postMessage(message);
  }
};
