import { DecimalPipe } from '@angular/common';
import { Component, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
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

/** The answer kinds of the statistics (rollup.answer_kind), in display order. */
const ANSWERS: Record<string, { label: string; hint: string }> = {
  address: { label: 'With an address', hint: 'An A/AAAA record in the answer: the total of the geolocation page' },
  no_address: { label: 'Without an address', hint: 'NOERROR with no A/AAAA: HTTPS, PTR, TXT, SRV, an AAAA for a name without IPv6...' },
  nxdomain: { label: 'Name does not exist', hint: 'NXDOMAIN from a zone or upstream (blocked names are counted apart)' },
  blocked: { label: 'Blocked', hint: 'Blocklist, suspicious name or rate limit' },
  error: { label: 'Failed', hint: 'SERVFAIL, REFUSED, upstream not answering' },
  proxied: { label: 'Through the proxy', hint: 'Web requests the filtering proxy let through (pages cleaned included)' },
  uncounted: { label: 'Not split yet', hint: 'Hours saved before this counter existed: manage.py rebuild_stats splits them' },
};

@Component({
  selector: 'app-stats-page',
  imports: [FormsModule, DecimalPipe, RouterLink],
  templateUrl: './stats-page.html',
})
export class StatsPage {
  private api = inject(Api);
  private ui = inject(Ui);
  stats = signal<Stats | null>(null);
  loading = signal(true);
  failed = signal(false);
  sel = signal(-1); // the chart bar shown in the readout line (-1: the latest)
  done = signal(new Set<string>());
  hours = 24;
  source: 'all' | 'dns' | 'proxy' = 'all';
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
    const sum = new Map<number, { count: number; blocked: number; proxy: number; pcount: number }>();
    for (const p of st.series) { const k = g.floor(new Date(p.t)).getTime(); const o = sum.get(k) ?? { count: 0, blocked: 0, proxy: 0, pcount: 0 }; sum.set(k, { count: o.count + p.count, blocked: o.blocked + p.blocked, proxy: o.proxy + p.proxy_blocked, pcount: o.pcount + p.proxy_count }); }
    const out: { at: number; count: number; blocked: number; proxy: number; pcount: number; label: string; tick: boolean; full: string }[] = [];
    const now = new Date();
    for (let d = g.floor(new Date(this.from())); d <= now && out.length < 400; d = g.next(d)) {
      const v = sum.get(d.getTime()); out.push({ at: d.getTime(), count: v?.count ?? 0, blocked: v?.blocked ?? 0, proxy: v?.proxy ?? 0, pcount: v?.pcount ?? 0, label: g.label(d), tick: true, full: d.toLocaleString([], { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' }) });
    }
    out.forEach((b, i) => b.tick = g.tick(new Date(b.at), i, out.length));  // after the loop: some grains label every bar when there are few
    return out;
  });

  private router = inject(Router);
  constructor() {
    const p = inject(ActivatedRoute).snapshot.queryParamMap; // ?hours=168&source=dns: a reload or a shared link keeps the view
    if ([1, 24, 168, 720].includes(Number(p.get('hours')))) this.hours = Number(p.get('hours'));
    if (p.get('source') === 'dns' || p.get('source') === 'proxy') this.source = p.get('source') as 'dns' | 'proxy';
    this.load();
  }
  /** The period or the source was changed: keep it in the URL, then load. */
  changed() {
    this.router.navigate([], { queryParams: { hours: this.hours !== 24 ? this.hours : null, source: this.source !== 'all' ? this.source : null }, replaceUrl: true });
    this.load();
  }

  load() {
    return this.ui.run(async () => {
      // 7 and 30 days are whole calendar days in the browser's time zone, today included: exactly 7 (or 30) bars, and the numbers above them
      // cover the same window as the chart
      let hours = this.hours, from = Date.now() - hours * 3_600_000, since: string | undefined;
      if (hours >= 168) {
        const first = new Date(); first.setHours(0, 0, 0, 0); first.setDate(first.getDate() - hours / 24 + 1);
        from = first.getTime(); hours = Math.min(Math.ceil((Date.now() - from) / 3_600_000), 720); since = first.toISOString();
      }
      this.loading.set(true);
      try {
        const st = await this.api.invoke(statsRetrieve, { hours, since, source: this.source });
        this.period.set(hours); this.from.set(from); this.stats.set(st); this.failed.set(false); this.sel.set(-1);
      } catch (e) { this.failed.set(true); throw e; }
      finally { this.loading.set(false); }
    });
  }
  block(name: string) {
    this.ui.ask(`Block ${name}?`, 'The domain and its subdomains will receive NXDOMAIN from the next query. Undo it in Blocklist > Personal blocks.', () =>
      this.ui.run(async () => {
        await this.api.invoke(blockedCreate, { body: { name } });
        this.done.update(s => new Set(s).add(name));
      }, { ok: `Blocked ${name}` }), 'Block domain');
  }

  /** Share of all queries that were blocked, one decimal. */
  rate = computed(() => { const st = this.stats(); return st?.total ? Math.round((this.outcome('blocked') / st.total) * 1000) / 10 : 0; });
  /** The log window for the chosen period (the log takes the same hours). */
  logQ(extra: { [k: string]: string } = {}) { return { ...(this.hours !== 24 ? { hours: this.hours } : {}), ...extra }; }
  /** Where a figure is listed: the DNS log, or the proxy log for proxy-only counts (it has no URL filters yet). */
  logPath() { return this.source === 'proxy' ? '/logs/proxy' : '/logs/dns'; }
  isDnsType(t: string) { return /^[A-Z0-9]+$/.test(t) && !['GET', 'POST', 'PUT', 'HEAD', 'DELETE', 'PATCH', 'OPTIONS', 'CONNECT'].includes(t); }

  // ---- the chart: a text summary, a readout line moved by pointer, tap or arrow keys ----
  /** Until the user picks one: the latest bar with queries (the current minute is often still empty). */
  private latest = computed(() => { const b = this.bars(); let i = b.length - 1; while (i > 0 && !b[i].count) i--; return i; });
  bar = computed(() => this.bars()[this.sel() < 0 ? this.latest() : this.sel()]);
  peak = computed(() => this.bars().reduce((a, b) => (b.count > (a?.count ?? -1) ? b : a), this.bars()[0]));
  summary = computed(() => {
    const st = this.stats(), p = this.peak();
    if (!st?.total || !p) return 'No queries in this period.';
    return `Queries per ${this.grain().name}: ${st.total.toLocaleString()} in all, ${this.outcome('blocked').toLocaleString()} blocked (${this.rate()}%). Busiest ${this.grain().name}: ${p.full} with ${p.count.toLocaleString()}. Use the arrow keys to read each ${this.grain().name}.`;
  });
  pickAt(e: PointerEvent) {
    const i = (e.target as HTMLElement).closest<HTMLElement>('[data-i]')?.dataset['i'];
    if (i !== undefined) this.sel.set(Number(i));
  }
  key(e: KeyboardEvent) {
    const n = this.bars().length, cur = this.sel() < 0 ? this.latest() : this.sel();
    const to = { ArrowLeft: cur - 1, ArrowRight: cur + 1, Home: 0, End: n - 1 }[e.key];
    if (to === undefined) return;
    e.preventDefault(); this.sel.set(Math.max(0, Math.min(n - 1, to)));
  }
  answers = computed(() => {
    const st = this.stats();
    if (!st?.total) return [];
    const n = (k: string) => st.by_answer.find(c => c.name === k)?.count ?? 0;
    const rest = st.total - st.by_answer.reduce((a, c) => a + c.count, 0);
    return Object.entries(ANSWERS).map(([name, v]) => ({ name, ...v, count: name === 'uncounted' ? Math.max(rest, 0) : n(name) })).filter(a => a.count);
  });
  share(c: number) { const t = this.stats()?.total; return t ? Math.round((c / t) * 100) : 0; }
  outcome(name: string) { return this.stats()?.by_outcome.find(c => c.name === name)?.count ?? 0; }
  pct(c: number, list: { count: number }[]) { return Math.round((c / Math.max(...list.map(x => x.count), 1)) * 100); }
}
