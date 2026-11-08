import { DecimalPipe } from '@angular/common';
import { Component, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Api } from '../api/api';
import { blockedCreate, statsRetrieve } from '../api/functions';
import { Stats } from '../api/models';
import { Ui } from '../services/ui';

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
  templateUrl: './stats-page.html',
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
