import type { AttackResult } from '../crypto/attack.js';
import { bin4, esc, hexNibble, percent, signed } from './format.js';

/**
 * The sixteen counters.
 *
 * While the attack is still counting, the true key is NOT marked — the whole
 * point is to watch a candidate separate on the evidence, and labelling the
 * answer in advance would turn the exhibit into an illustration of itself. The
 * marker appears only once counting has finished.
 */
export interface RankingOptions {
  readonly reveal: boolean;
  /** Sort by score, or keep candidates in a fixed order so bars can be watched. */
  readonly order: 'ranked' | 'fixed';
}

export function renderCounters(table: HTMLTableElement, result: AttackResult, options: RankingOptions): void {
  const top = Math.max(...result.scores.map((s) => s.deviation), 1e-9);
  const rows = (options.order === 'ranked' ? result.ranked : result.scores).map((score) => {
    const isCorrect = score.guess === result.trueNibble;
    const isPick = score.guess === result.ranked[0].guess;
    const width = Math.max(1, (score.deviation / top) * 100);
    const markers: string[] = [];
    if (options.reveal && isCorrect) markers.push('<span class="marker is-key">actual key</span>');
    if (options.reveal && isPick) markers.push('<span class="marker is-pick">attack picked</span>');
    const classes = [
      options.reveal && isCorrect ? 'is-correct' : '',
      options.reveal && isPick && !isCorrect ? 'is-wrong-pick' : '',
    ]
      .filter(Boolean)
      .join(' ');
    const rank = result.ranked.findIndex((s) => s.guess === score.guess) + 1;
    return `
      <tr class="${classes}">
        <td class="num">${options.reveal ? rank : '·'}</td>
        <td class="num candidate">${hexNibble(score.guess)} <span class="dim">${bin4(score.guess)}</span>${markers.join('')}</td>
        <td class="num">${score.matches.toLocaleString()}</td>
        <td class="num">${signed(score.bias)}</td>
        <td class="bar-cell"><div class="rank-bar" style="width:${width}%"></div></td>
      </tr>`;
  });

  table.innerHTML = `
    ${table.querySelector('caption')?.outerHTML ?? ''}
    <thead>
      <tr>
        <th scope="col" class="num">#</th>
        <th scope="col" class="num">Key guess</th>
        <th scope="col" class="num">Held</th>
        <th scope="col" class="num">Bias</th>
        <th scope="col">Distance from a coin flip</th>
      </tr>
    </thead>
    <tbody>${rows.join('')}</tbody>
  `;
}

/** The idle state: sixteen candidates, no evidence yet, nothing pretended. */
export function renderCountersIdle(table: HTMLTableElement): void {
  const rows = Array.from({ length: 16 }, (_, guess) => `
      <tr>
        <td class="num">·</td>
        <td class="num candidate">${hexNibble(guess)} <span class="dim">${bin4(guess)}</span></td>
        <td class="num">—</td>
        <td class="num">—</td>
        <td class="bar-cell"><div class="rank-bar is-empty" style="width:1%"></div></td>
      </tr>`).join('');
  table.innerHTML = `
    ${table.querySelector('caption')?.outerHTML ?? ''}
    <thead>
      <tr>
        <th scope="col" class="num">#</th>
        <th scope="col" class="num">Key guess</th>
        <th scope="col" class="num">Held</th>
        <th scope="col" class="num">Bias</th>
        <th scope="col">Distance from a coin flip</th>
      </tr>
    </thead>
    <tbody>${rows}</tbody>
  `;
}

export type CockpitPhase = 'idle' | 'stale' | 'counting' | 'done' | 'blocked';

export interface StatusOptions {
  readonly phase: CockpitPhase;
  readonly processed: number;
  readonly total: number;
  readonly message?: string;
}

/**
 * One line that always says what the counters on screen actually represent.
 * A result left standing under changed controls is the single most misleading
 * thing this page could do, so "stale" is a first-class state, not a nuance.
 */
export function renderStatus(el: HTMLElement, options: StatusOptions): void {
  const { phase, processed, total } = options;
  const pct = total > 0 ? Math.round((processed / total) * 100) : 0;
  let icon = '';
  let text = '';
  switch (phase) {
    case 'idle':
      icon = '○';
      text = 'No evidence collected yet. Press Run to count.';
      break;
    case 'stale':
      icon = '↻';
      text = 'Configuration changed — run again. The counters below are from the previous settings.';
      break;
    case 'counting':
      icon = '◐';
      text = `Counting ${processed.toLocaleString()} of ${total.toLocaleString()} pairs (${pct}%)`;
      break;
    case 'done':
      icon = '●';
      text = `Counted ${total.toLocaleString()} known ${total === 1 ? 'pair' : 'pairs'}.`;
      break;
    case 'blocked':
      icon = '!';
      text = options.message ?? 'This approximation cannot be run.';
      break;
  }
  el.className = `run-status is-${phase}`;
  el.innerHTML = `<span class="run-status-icon" aria-hidden="true">${icon}</span><span>${esc(text)}</span>`;
  const bar = phase === 'counting' ? `<div class="run-progress"><div style="width:${pct}%"></div></div>` : '';
  el.insertAdjacentHTML('beforeend', bar);
}

/**
 * The four-stage chain from one S-box's imbalance to one key candidate. Every
 * number here is produced by the current configuration; nothing is illustrative.
 */
export interface MechanismStage {
  readonly id: string;
  readonly target: string;
  readonly label: string;
  readonly value: string;
  readonly note: string;
  readonly pending: boolean;
}

export function renderMechanism(el: HTMLElement, stages: readonly MechanismStage[]): void {
  el.innerHTML = stages
    .map(
      (stage, index) => `
        <li class="mech-stage${stage.pending ? ' is-pending' : ''}">
          <a class="mech-link" href="#${stage.target}">
            <span class="mech-index" aria-hidden="true">${index + 1}</span>
            <span class="mech-body">
              <span class="mech-label">${stage.label}</span>
              <span class="mech-value">${stage.value}</span>
              <span class="mech-note">${stage.note}</span>
            </span>
          </a>
        </li>`,
    )
    .join('<li class="mech-arrow" aria-hidden="true">↓</li>');
}

/** Progress readout for the off-thread measurement. */
export function renderMeasureProgress(el: HTMLElement, completed: number, total: number): void {
  const pct = total > 0 ? Math.round((completed / total) * 100) : 0;
  el.innerHTML = `
    <p class="measure-progress-text">${completed.toLocaleString()} / ${total.toLocaleString()} complete attacks run (${percent(
      completed / Math.max(1, total),
      0,
    )})</p>
    <div class="run-progress"><div style="width:${pct}%"></div></div>
  `;
}
