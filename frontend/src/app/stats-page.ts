import { DecimalPipe } from '@angular/common';
import { Component, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Api } from './api/api';
import { blockedCreate, statsRetrieve } from './api/functions';
import { Stats } from './api/models';
import { Ui } from './ui';

const hm = (d: Date) => d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
const dm = (d: Date) => d.toLocaleDateString([], { day: '2-digit', month: '2-digit' });
/** One bar of the chart = one bucket in the browser's time zone: floor() is its start, next() the start of the following one. */
const GRAINS = {
  minute: { name: 'minute', floor: (d: Date) => { d.setSeconds(0, 0); return d; }, next: (d: Date) => new Date(d.getTime() + 60_000), label: hm, tick: (d: Date) => d.getMinutes() % 5 === 0 },
  hour: { name: 'hour', floor: (d: Date) => { d.setMinutes(0, 0, 0); return d; }, next: (d: Date) => { const n = new Date(d); n.setHours(n.getHours() + 1); return n; }, label: hm, tick: (d: Date) => d.getHours() % 2 === 0 },
  day: { name: 'day', floor: (d: Date) => { d.setHours(0, 0, 0, 0); return d; }, next: (d: Date) => { const n = new Date(d); n.setDate(n.getDate() + 1); return n; }, label: dm, tick: (_: Date, i: number, n: number) => n <= 10 || i % 3 === 0 },
};

@Component({
  selector: 'app-stats-page',
  imports: [FormsModule, DecimalPipe],
  template: `
    @if (stats(); as st) {
      <header>
        <div>
          <h2>Statistics</h2>
          <p class="soft">Queries received by the DNS daemon.</p>
        </div>
        <div class="actions">
          <select [(ngModel)]="hours" name="h" (ngModelChange)="load()" aria-label="Period">
            <option [ngValue]="1">Last hour</option>
            <option [ngValue]="24">Last 24 hours</option>
            <option [ngValue]="168">Last 7 days</option>
            <option [ngValue]="720">Last 30 days</option>
          </select>
          <button class="ghost" (click)="load()">Refresh</button>
        </div>
      </header>

      <div class="tiles">
        <div class="tile"><b>{{ st.total }}</b><span>Query</span></div>
        <div class="tile"><b>{{ outcome('local') }}</b><span>From internal zones</span></div>
        <div class="tile"><b>{{ outcome('forwarded') }}</b><span>Forwarded</span></div>
        <div class="tile warn"><b>{{ outcome('blocked') }}</b><span>Blocked</span></div>
        <div class="tile"><b>{{ st.avg_ms | number: '1.0-0' }} ms</b><span>Average time</span></div>
      </div>

      <section class="panel">
        <h3>Queries per {{ grain().name }}</h3>
        @if (st.total) {
          <div class="chart" [class.dense]="bars().length > 30">
            @for (p of bars(); track p.at) {
              <div class="col" [title]="p.full + ': ' + p.count" [style.--h]="pct(p.count, bars()) + '%'">
                <b>{{ p.count }}</b>
                <i [style.height.%]="pct(p.count, bars())"></i>
                <span [class.off]="!p.tick">{{ p.label }}</span>
              </div>
            }
          </div>
        } @else { <p class="soft">No queries in this period.</p> }
      </section>

      <div class="grid2">
        <section class="panel">
          <h3>Most requested domains</h3>
          @for (d of st.top_domains; track d.name) {
            <div class="row">
              <span class="bar" [style.width.%]="pct(d.count, st.top_domains)"></span>
              <span class="n">{{ d.name }}</span><span class="c">{{ d.count }}</span>
              @if (done().has(d.name)) { <span class="soft">Blocked</span> }
              @else { <button class="mini" (click)="block(d.name)" [attr.aria-label]="'Block ' + d.name">Block</button> }
            </div>
          } @empty { <p class="soft">No data.</p> }
        </section>
        <section class="panel">
          <h3>Most requested blocked domains</h3>
          @for (d of st.top_blocked; track d.name) {
            <div class="row"><span class="bar warn" [style.width.%]="pct(d.count, st.top_blocked)"></span><span class="n">{{ d.name }}</span><span class="c">{{ d.count }}</span></div>
          } @empty { <p class="soft">No blocked queries.</p> }
        </section>
        <section class="panel">
          <h3>Most active clients</h3>
          @for (d of st.top_clients; track d.name) {
            <div class="row"><span class="bar" [style.width.%]="pct(d.count, st.top_clients)"></span><span class="n">{{ d.name }}</span><span class="c">{{ d.count }}</span></div>
          } @empty { <p class="soft">No data.</p> }
        </section>
        <section class="panel">
          <h3>Query types</h3>
          @for (d of st.by_type; track d.name) {
            <div class="row"><span class="bar" [style.width.%]="pct(d.count, st.by_type)"></span><span class="n">{{ d.name }}</span><span class="c">{{ d.count }}</span></div>
          } @empty { <p class="soft">No data.</p> }
        </section>
      </div>
    }`,
})
export class StatsPage {
  private api = inject(Api);
  private ui = inject(Ui);
  stats = signal<Stats | null>(null);
  done = signal(new Set<string>());
  hours = 24;
  private period = signal(24); // the period the shown data was loaded for (the chart follows it, not the select while it is changing)
  private from = signal(Date.now()); // where the shown window starts

  /** Chart sampling follows the period: minutes for the last hour, hours for a day, whole days (one bar each, today included) for 7 and 30 days. */
  grain = computed(() => {
    const h = this.period();
    return h <= 2 ? GRAINS.minute : h <= 48 ? GRAINS.hour : GRAINS.day;
  });
  bars = computed(() => {
    const st = this.stats(), g = this.grain();
    if (!st) return [];
    const sum = new Map<number, number>();
    for (const p of st.series) { const k = g.floor(new Date(p.t)).getTime(); sum.set(k, (sum.get(k) ?? 0) + p.count); }
    const out: { at: number; count: number; label: string; tick: boolean; full: string }[] = [];
    const now = new Date();
    for (let d = g.floor(new Date(this.from())); d <= now && out.length < 400; d = g.next(d)) {
      out.push({ at: d.getTime(), count: sum.get(d.getTime()) ?? 0, label: g.label(d), tick: true, full: d.toLocaleString([], { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' }) });
    }
    out.forEach((b, i) => b.tick = g.tick(new Date(b.at), i, out.length));  // after the loop: some grains label every bar when there are few
    return out;
  });

  constructor() { this.load(); }

  load() {
    return this.ui.run(async () => {
      // 7 and 30 days are whole calendar days in the browser's time zone, today included: exactly 7 (or 30) bars, and the numbers above them
      // cover the same window as the chart
      let hours = this.hours, from = Date.now() - hours * 3_600_000, since: string | undefined;
      if (hours >= 168) {
        const first = new Date(); first.setHours(0, 0, 0, 0); first.setDate(first.getDate() - hours / 24 + 1);
        from = first.getTime(); hours = Math.min(Math.ceil((Date.now() - from) / 3_600_000), 720); since = first.toISOString();
      }
      const st = await this.api.invoke(statsRetrieve, { hours, since });
      this.period.set(hours); this.from.set(from); this.stats.set(st);
    });
  }
  block(name: string) {
    return this.ui.run(async () => {
      await this.api.invoke(blockedCreate, { body: { name } });
      this.done.update(s => new Set(s).add(name));
    });
  }
  outcome(name: string) { return this.stats()?.by_outcome.find(c => c.name === name)?.count ?? 0; }
  pct(c: number, list: { count: number }[]) { return Math.round((c / Math.max(...list.map(x => x.count), 1)) * 100); }
}
