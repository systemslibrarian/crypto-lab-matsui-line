import type { TraceStage } from '../crypto/spn.js';
import { bin8, esc, hex } from './format.js';

/**
 * The encryption walkthrough. Every observable state of one encryption is
 * printed in binary, because the attack is a statement about individual bits
 * and hex hides exactly the thing being taught.
 */
export function renderTrace(container: HTMLElement, stages: readonly TraceStage[]): void {
  container.innerHTML = stages
    .map((stage) => {
      const classes = ['trace-stage'];
      if (stage.isTargetState) classes.push('is-target');
      if (stage.kind === 'sbox') classes.push('is-sbox');
      const tag = stage.isTargetState ? '<span class="trace-tag">attack target</span>' : '';
      return `
        <div class="${classes.join(' ')}">
          <span class="trace-label">${esc(stage.label)}</span>
          <span class="trace-bits">${bin8(stage.state)}</span>
          <span class="trace-hex">${hex(stage.state)}</span>
          ${tag}
        </div>`;
    })
    .join('');
}
