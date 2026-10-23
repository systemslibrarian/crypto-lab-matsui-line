import { observeAdvanced, type RelationCount } from '../crypto/advanced.js';
import { hex } from './format.js';

/** Show counted outcomes for two mask relations and a no-trail relation. */
export function mountAdvanced(panel: HTMLElement): void {
  const keyControl = panel.querySelector<HTMLSelectElement>('#advanced-key');
  const sampleControl = panel.querySelector<HTMLSelectElement>('#advanced-samples');
  const output = panel.querySelector<HTMLElement>('#advanced-results');
  if (!keyControl || !sampleControl || !output) throw new Error('missing advanced linear-analysis controls');

  const relation = (label: string, value: RelationCount, total: number): string => {
    const bias = value.matches / total - 0.5;
    const signed = bias > 0 ? '+' : '';
    return `<tr><th scope="row">${label}</th><td><code>${hex(value.startMask)} → ${hex(value.endMask)}</code></td>` +
      `<td>${value.matches}/${total}</td><td>${signed}${bias.toFixed(4)}</td></tr>`;
  };

  const render = (): void => {
    const samples = Number(sampleControl.value) as 16 | 64 | 256;
    const result = observeAdvanced(Number(keyControl.value), samples);
    output.innerHTML = `
      <div class="advanced-grid">
        <div class="advanced-table" role="region" tabindex="0" aria-label="Measured linear relations">
          <table><caption>Parity agreements over ${samples} distinct plaintexts</caption>
            <thead><tr><th scope="col">Relation</th><th scope="col">Input → pre-final mask</th><th scope="col">Agreements</th><th scope="col">Measured bias</th></tr></thead>
            <tbody>${relation('A', result.relations[0], samples)}${relation('B', result.relations[1], samples)}${relation('No-trail pair', result.structuralZero, samples)}</tbody>
          </table>
        </div>
        <div class="advanced-table" role="region" tabindex="0" aria-label="Joint mask outcomes">
          <table><caption>Count the two relations together</caption>
            <thead><tr><th scope="col">A holds?</th><th scope="col">B holds?</th><th scope="col">Count</th></tr></thead>
            <tbody>${result.jointCounts.map((count, index) => `<tr><td>${index & 2 ? 'yes' : 'no'}</td><td>${index & 1 ? 'yes' : 'no'}</td><td>${count}</td></tr>`).join('')}</tbody>
          </table>
        </div>
      </div>
      <p class="footnote">The joint counts are measured from the <em>same</em> plaintexts. Two separate biases do not tell you their four joint frequencies; assuming they are independent would be an extra claim.</p>
      <p class="callout"><strong>${result.noNonzeroTrail ? 'No nonzero two-round trail joins the third mask pair.' : 'Trail analysis could not establish a structural zero.'}</strong>
        Its whole-codebook correlation is exactly zero for every round key in this toy, because each possible trail contains a zero-correlation step.
        ${samples === 256 ? `This selected key has ${result.structuralZero.matches}/256 agreements: the full population, not a sample.` : `This ${samples}-plaintext sample has ${result.structuralZero.matches}/${samples} agreements; a finite sample may look biased even when the population correlation is zero.`}
        A different relation may measure zero for one key through cancellation without being structurally zero.</p>`;
  };
  keyControl.addEventListener('change', render);
  sampleControl.addEventListener('change', render);
  render();
}
