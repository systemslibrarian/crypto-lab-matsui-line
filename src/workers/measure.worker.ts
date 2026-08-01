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
}

export type MeasureMessage =
  | { readonly kind: 'progress'; readonly completed: number; readonly total: number }
  | { readonly kind: 'done'; readonly points: SuccessPoint[]; readonly seed: number }
  | { readonly kind: 'error'; readonly message: string };

self.onmessage = (event: MessageEvent<MeasureRequest>) => {
  const request = event.data;
  try {
    let lastPost = 0;
    const points = measureSuccessRate({
      sbox: getSbox(request.sboxName),
      cipherRounds: request.cipherRounds,
      half: request.half,
      startMask: request.startMask,
      endMask: request.endMask,
      sampleCounts: request.sampleCounts,
      keyCount: request.keyCount,
      bias: request.bias,
      seed: request.seed,
      onProgress: (completed, total) => {
        // Post at most every 8 attacks: enough to look live, few enough that
        // messaging does not become the bottleneck it is reporting on.
        if (completed === total || completed - lastPost >= 8) {
          lastPost = completed;
          const message: MeasureMessage = { kind: 'progress', completed, total };
          self.postMessage(message);
        }
      },
    });
    const message: MeasureMessage = { kind: 'done', points, seed: request.seed };
    self.postMessage(message);
  } catch (error) {
    const message: MeasureMessage = {
      kind: 'error',
      message: error instanceof Error ? error.message : String(error),
    };
    self.postMessage(message);
  }
};
