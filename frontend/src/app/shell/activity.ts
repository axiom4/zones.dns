import { DecimalPipe } from '@angular/common';
import { Component, DestroyRef, computed, inject, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { Api } from '../api/api';
import { statsRetrieve } from '../api/functions';
import { MINUTES, byMinute } from '../lib/activity';

const W = 120, H = 28;

/** The live trace at the top of every page: queries per minute over the last hour, blocked ones in red, and a status LED.
 * Refreshed every 30 s while the page is visible (the server keeps the answer 30 s). */
@Component({
  selector: 'app-activity',
  imports: [RouterLink, DecimalPipe],
  template: `
    <a routerLink="/stats" class="activity" [attr.aria-label]="label()" [title]="label()">
      <span class="led" [attr.data-s]="state()" aria-hidden="true"></span>
      <svg class="trace" [attr.viewBox]="'0 0 ' + W + ' ' + H" preserveAspectRatio="none" aria-hidden="true">
        <path class="area" [attr.d]="paths().area" />
        <path class="line" [attr.d]="paths().all" />
        <path class="blk" [attr.d]="paths().blocked" />
      </svg>
      <span class="num"><b>{{ perMin() | number }}</b> <span>per min</span></span>
      <span class="num pct"><b>{{ pct() }}%</b> <span>blocked</span></span>
    </a>`,
})
export class Activity {
  private api = inject(Api);
  protected readonly W = W; protected readonly H = H;
  private counts = signal<number[]>([]);
  private blocked = signal<number[]>([]);
  private failed = signal(false);

  constructor() {
    const tick = () => { if (!document.hidden) this.load(); };
    const id = setInterval(tick, 30000);
    document.addEventListener('visibilitychange', tick);
    inject(DestroyRef).onDestroy(() => { clearInterval(id); document.removeEventListener('visibilitychange', tick); });
    this.load();
  }

  private async load() {
    try {
      const s = await this.api.invoke(statsRetrieve, { hours: 1 });
      const [c, b] = byMinute(s.series, Date.now());
      this.counts.set(c); this.blocked.set(b); this.failed.set(false);
    } catch {
      this.failed.set(true); // not a page error: the strip just says it has no data
    }
  }

  /** queries per minute: the mean of the last 5 minutes (the current one is still filling) */
  perMin = computed(() => Math.round(this.counts().slice(-6, -1).reduce((a, b) => a + b, 0) / 5));
  pct = computed(() => {
    const all = this.counts().reduce((a, b) => a + b, 0), blk = this.blocked().reduce((a, b) => a + b, 0);
    return all ? Math.round((blk / all) * 100) : 0;
  });
  state = computed(() => this.failed() ? 'off' : this.counts().slice(-3).some(n => n > 0) ? 'ok' : this.counts().some(n => n > 0) ? 'idle' : 'off');
  label = computed(() => this.failed() ? 'Activity unavailable. Open statistics.'
    : this.state() === 'off' ? 'No queries in the last hour. Open statistics.'
    : `${this.perMin()} queries a minute, ${this.pct()}% blocked in the last hour${this.state() === 'idle' ? ', quiet for the last 3 minutes' : ''}. Open statistics.`);
  paths = computed(() => {
    const c = this.counts(), b = this.blocked();
    const max = Math.max(1, ...c);
    const pt = (v: number, i: number) => `${((i / (MINUTES - 1)) * W).toFixed(1)},${(H - 2 - (v / max) * (H - 4)).toFixed(1)}`;
    const line = (vs: number[]) => vs.length ? 'M' + vs.map(pt).join(' L') : '';
    const all = line(c);
    return { all, blocked: line(b), area: all ? `${all} L${W},${H} L0,${H} Z` : '' };
  });
}
