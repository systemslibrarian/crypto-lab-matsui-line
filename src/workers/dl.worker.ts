/**
 * The differential–linear success-rate measurement runs up to
 * 5 budgets × 512 keys × 256 candidate guesses × 128 pairs of real cipher
 * work — millions of S-box lookups. Like the linear lab's measurement, it
 * runs off the main thread and reports real progress, so the count being
 * watched is the count being performed.
 */

import { ALIGNED, CANCELLED, measureDlSuccessRate, type DlSuccessPoint } from '../crypto/difflin.js';
import { getSbox, type SboxName } from '../crypto/sbox.js';

export interface DlMeasureRequest {
  readonly sboxName: SboxName;
  readonly designName: 'aligned' | 'cancelled';
  readonly budgets: number[];
  readonly keyCount: number;
}

export type DlMeasureMessage =
  | { readonly kind: 'progress'; readonly completed: number; readonly total: number }
  | { readonly kind: 'done'; readonly points: DlSuccessPoint[] }
  | { readonly kind: 'error'; readonly message: string };

self.onmessage = (event: MessageEvent<DlMeasureRequest>) => {
  const request = event.data;
  try {
    let lastPost = 0;
    const points = measureDlSuccessRate({
      sbox: getSbox(request.sboxName),
      design: request.designName === 'aligned' ? ALIGNED : CANCELLED,
      budgets: request.budgets,
      keyCount: request.keyCount,
      onProgress: (completed, total) => {
        // Post at most every 8 keys: enough to look live, few enough that
        // messaging does not become the bottleneck it is reporting on.
        if (completed === total || completed - lastPost >= 8) {
          lastPost = completed;
          const message: DlMeasureMessage = { kind: 'progress', completed, total };
          self.postMessage(message);
        }
      },
    });
    const message: DlMeasureMessage = { kind: 'done', points };
    self.postMessage(message);
  } catch (error) {
    const message: DlMeasureMessage = {
      kind: 'error',
      message: error instanceof Error ? error.message : String(error),
    };
    self.postMessage(message);
  }
};
