/*
 * ROUTE (add inside the Shell children of app.routes.ts):
 *   { path: 'device/:client', title: 'Device story', loadComponent: () => import('./device-story/device-story').then(m => m.DeviceStoryPage) },
 *
 * LINK (e.g. an extra cell in the leases / clients table; `l.address` or any client IP, or a name of the default zone):
 *   <a class="mini" [routerLink]="['/device', l.address]">Story</a>      // add RouterLink to the component's imports
 *
 * Uses only existing endpoints: logs (client filter, paged by id), logs/grouped, logs/clients, logs/resolved, geo/ips,
 * dhcp/leases, dhcp/ping, blocked (create). Stats and geo/destinations have no client filter, so they are not used.
 */
import { DatePipe, DecimalPipe } from '@angular/common';
import { Component, OnDestroy, computed, inject, signal } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { ActivatedRoute, RouterLink } from '@angular/router';
import { Api } from '../api/api';
import { blockedCreate, dhcpLeasesList, geoIpsRetrieve, logsClientsList, logsGroupedList, logsList, logsResolvedList } from '../api/functions';
import { DhcpLease, DhcpPingResult, QueryLog, QueryLogGroup } from '../api/models';
import { countryName, flag } from '../lib/geo-util';
import { Ping } from '../services/ping';
import { Period } from '../services/period';
import { Ui } from '../services/ui';

type Range = 24 | 168;
interface Cell { start: number; count: number; blocked: number }
interface Part<T> { loading: boolean; error: string; data: T }
interface Dom { g: QueryLogGroup; subs: QueryLogGroup[] | null; open: boolean; busy: boolean }
interface Country { code: string; queries: number }

const PAGE = 500, MAX_PAGES = 4; // ribbon: at most 2000 newest rows
const HOUR = 3600_000;
const part = <T>(data: T): Part<T> => ({ loading: true, error: '', data });
const fail = (e: any) => e?.error?.detail ?? `Could not load (HTTP ${e?.status ?? 'no answer'}).`;
const isIp = (s: string) => /^[0-9.]+$/.test(s) || (s.includes(':') && /^[0-9a-f:.]+$/i.test(s));

@Component({
  selector: 'app-device-story',
  imports: [DatePipe, DecimalPipe, RouterLink],
  templateUrl: './device-story.html',
  styleUrl: './device-story.css',
})
export class DeviceStoryPage implements OnDestroy {
  private api = inject(Api);
  private ping = inject(Ping);
  ui = inject(Ui);
  private gen = 0; // a newer load (route or range change, destroy) makes the older answers be dropped
  countryName = countryName; flag = flag;

  param = signal('');
  ip = signal('');
  host = signal('');
  private periodStore = inject(Period);
  range = signal<Range>(this.periodStore.pick([24, 168]) as Range);
  lease = signal<DhcpLease | null>(null);
  vendor = computed(() => this.lease()?.vendor || '');
  pingRes = signal<DhcpPingResult | null>(null);
  pinging = signal(false);
  head = signal<Part<null>>(part(null));
  ribbon = signal<Part<{ cells: Cell[]; total: number; shown: number }>>(part({ cells: [], total: 0, shown: 0 }));
  tops = signal<Part<Dom[]>>(part([]));
  fresh = signal<Part<{ g: QueryLogGroup }[]>>(part([]));
  blocked = signal<Part<QueryLogGroup[]>>(part([]));
  geo = signal<Part<Country[]>>(part([]));
  done = signal(new Set<string>()); // names blocked or allowed from this page
  sel = signal(-1);

  name = computed(() => this.host() || this.lease()?.hostname || this.param());
  maxCount = computed(() => Math.max(1, ...this.ribbon().data.cells.map(c => c.count)));
  selCell = computed(() => this.ribbon().data.cells[this.sel()] ?? null);
  topMax = computed(() => Math.max(1, ...this.tops().data.map(d => d.g.count)));
  geoMax = computed(() => Math.max(1, ...this.geo().data.map(c => c.queries)));
  pingText = computed(() => { const r = this.pingRes(); return !r ? '' : r.error ? r.error : r.up ? `Online${r.ms != null ? ', ' + r.ms + ' ms' : ''}` : 'No answer to ping'; });

  /** One paragraph built from the numbers on screen; nothing leaves the browser. */
  summary = computed(() => {
    const r = this.ribbon(), t = this.tops().data;
    if (r.loading || this.tops().loading) return '';
    const per = this.range() === 24 ? 'in the last 24 hours' : 'in the last 7 days';
    if (!r.data.total) return `${this.name()} made no DNS queries ${per}.`;
    const blocked = t.reduce((n, d) => n + d.g.blocked, 0), all = t.reduce((n, d) => n + d.g.count, 0);
    const pct = all ? Math.round(blocked * 100 / all) : 0;
    const f = (n: number) => n.toLocaleString();
    let s = `${this.name()} made ${f(r.data.total)} queries ${per}, to ${t.length}${t.length >= 50 ? '+' : ''} registrable domains; ${pct}% of the top ones were blocked.`;
    const busy = r.data.cells.reduce((b, c) => (c.count > b.count ? c : b), r.data.cells[0]);
    if (busy?.count) s += ` The busiest hour was ${new Date(busy.start).toLocaleString([], { weekday: 'short', hour: '2-digit', minute: '2-digit' })} (${f(busy.count)} queries).`;
    if (t[0]) s += ` It talked most to ${t[0].g.name} (${f(t[0].g.count)}).`;
    const n = this.fresh().data.length;
    s += n ? ` ${n} ${n === 1 ? 'domain is' : 'domains are'} new today: never contacted in the 7 days before.` : ' Nothing new today compared with the previous 7 days.';
    const c = this.geo().data[0];
    if (c) s += ` Most answers pointed to ${countryName(c.code)}.`;
    return s;
  });

  constructor() {
    inject(ActivatedRoute).paramMap.pipe(takeUntilDestroyed()).subscribe(p => { this.param.set((p.get('client') ?? '').trim()); this.load(); });
  }
  ngOnDestroy() { this.gen++; }

  setRange(r: Range) { if (r !== this.range()) { this.periodStore.remember(r); this.range.set(r); this.sel.set(-1); this.loadRange(this.gen); } }

  async load() {
    const g = ++this.gen;
    this.head.set(part(null)); this.fresh.set(part([])); this.lease.set(null); this.pingRes.set(null); this.host.set(''); this.sel.set(-1);
    const p = this.param();
    if (!p) { this.head.set({ loading: false, error: 'No device given.', data: null }); return; }
    try {
      let ip = p;
      if (!isIp(p)) { // a name: the log's client list knows which address it belongs to
        const cs = await this.api.invoke(logsClientsList, { hours: 720 });
        const c = cs.find(x => x.host === p.toLowerCase() || x.name === p.toLowerCase());
        if (g !== this.gen) return;
        if (!c) { this.head.set({ loading: false, error: `No client called ${p} in the last 30 days.`, data: null }); return; }
        ip = c.ip; this.host.set(c.host);
      }
      this.ip.set(ip); this.head.set({ loading: false, error: '', data: null });
    } catch (e) { if (g === this.gen) this.head.set({ loading: false, error: fail(e), data: null }); return; }
    this.loadRange(g);
    this.loadHeader(g); this.loadFresh(g);
  }

  private async loadHeader(g: number) {
    const ip = this.ip();
    try { // a lease gives the card maker and the host name; having none is normal (static address)
      const l = (await this.api.invoke(dhcpLeasesList, { q: ip, all: true })).find(x => x.address === ip);
      if (g === this.gen) this.lease.set(l ?? null);
    } catch { /* optional */ }
    this.pingNow(g);
  }
  async pingNow(g = this.gen) {
    if (this.pinging()) return; // one in flight
    this.pinging.set(true);
    try { const r = await this.ping.once(this.ip()); if (g === this.gen) this.pingRes.set(r); } catch { /* optional */ }
    finally { this.pinging.set(false); }
  }

  /** Ribbon, top domains and countries follow the range. */
  private loadRange(g: number) {
    this.ribbon.set(part({ cells: [], total: 0, shown: 0 })); this.tops.set(part([])); this.geo.set(part([])); this.blocked.set(part([]));
    this.loadRibbon(g); this.loadTops(g); this.loadBlocked(g);
  }

  private async loadRibbon(g: number) {
    const hours = this.range(), ip = this.ip(), now = Date.now();
    const first = Math.floor(now / HOUR) * HOUR - (hours - 1) * HOUR;
    const cells: Cell[] = Array.from({ length: hours }, (_, i) => ({ start: first + i * HOUR, count: 0, blocked: 0 }));
    let before: number | undefined, shown = 0, total = 0;
    try {
      for (let i = 0; i < MAX_PAGES; i++) {
        const r = await this.api.invoke(logsList, { client: ip, hours, limit: PAGE, before });
        if (g !== this.gen) return;
        total = r.count;
        for (const q of r.results as QueryLog[]) {
          const c = cells[Math.floor((Date.parse(q.time) - first) / HOUR)];
          if (c) { c.count++; if (q.outcome === 'blocked') c.blocked++; }
        }
        shown += r.results.length;
        if (!r.results.length || shown >= total) break;
        before = r.results[r.results.length - 1].id;
      }
      this.ribbon.set({ loading: false, error: '', data: { cells, total, shown } });
    } catch (e) { if (g === this.gen) this.ribbon.set({ loading: false, error: fail(e), data: { cells, total: 0, shown: 0 } }); }
  }

  /** The domains the filter stopped for this device in the period, alphabetical (the 50 most asked). */
  private async loadBlocked(g: number) {
    try {
      const r = await this.api.invoke(logsGroupedList, { client: this.ip(), hours: this.range(), by: 'domain', outcome: 'blocked', ordering: 'count', limit: 50 });
      if (g === this.gen) this.blocked.set({ loading: false, error: '', data: [...r.results].sort((a, b) => a.name.localeCompare(b.name)) });
    } catch (e) { if (g === this.gen) this.blocked.set({ loading: false, error: fail(e), data: [] }); }
  }

  private async loadTops(g: number) {
    try {
      const r = await this.api.invoke(logsGroupedList, { client: this.ip(), hours: this.range(), by: 'domain', ordering: 'count', limit: 50 });
      if (g !== this.gen) return;
      this.tops.set({ loading: false, error: '', data: r.results.map(x => ({ g: x, subs: null, open: false, busy: false })) });
      this.loadGeo(g, r.results.slice(0, 15));
    } catch (e) { if (g === this.gen) this.tops.set({ loading: false, error: fail(e), data: [] }); }
  }

  /** Per-client country data does not exist in the API: resolve the top domains' addresses and locate them (50 addresses at most). */
  private async loadGeo(g: number, top: QueryLogGroup[]) {
    try {
      if (!top.length) { this.geo.set({ loading: false, error: '', data: [] }); return; }
      const res = await this.api.invoke(logsResolvedList, { by: 'domain', names: top.map(t => t.name).join(',') });
      const ips = [...new Set(res.flatMap(r => r.resolved.filter(a => a.type === 'A' || a.type === 'AAAA').map(a => a.value)))].slice(0, 50);
      if (!ips.length) { if (g === this.gen) this.geo.set({ loading: false, error: '', data: [] }); return; }
      const loc = new Map((await this.api.invoke(geoIpsRetrieve, { ips: ips.join(',') })).results.map(x => [x.ip, x]));
      if (g !== this.gen) return;
      const by = new Map<string, number>();
      for (const r of res) {
        const w = top.find(t => t.name === r.name)?.count ?? 0;
        const codes = new Set(r.resolved.map(a => loc.get(a.value)).filter(x => !!x).map(x => (x!.private ? 'PRIV' : x!.country || '??')));
        for (const c of codes) by.set(c, (by.get(c) ?? 0) + w);
      }
      this.geo.set({ loading: false, error: '', data: [...by].map(([code, queries]) => ({ code, queries })).sort((a, b) => b.queries - a.queries).slice(0, 12) });
    } catch (e) { if (g === this.gen) this.geo.set({ loading: false, error: fail(e), data: [] }); }
  }

  /** NEW = every query of the last 8 days is in the last 24 hours, i.e. nothing in the 7 days before today. */
  private async loadFresh(g: number) {
    const base = { client: this.ip(), by: 'domain' as const, limit: 200 };
    try {
      const [day, week] = await Promise.all([
        this.api.invoke(logsGroupedList, { ...base, hours: 24 }),
        this.api.invoke(logsGroupedList, { ...base, hours: 192 }),
      ]);
      if (g !== this.gen) return;
      const before = new Map(week.results.map(w => [w.name, w.count]));
      // a domain missing from the (capped) week list cannot be judged: not flagged
      const data = day.results.filter(d => before.has(d.name) && before.get(d.name) === d.count).map(g => ({ g })).sort((a, b) => a.g.name.localeCompare(b.g.name));
      this.fresh.set({ loading: false, error: '', data });
    } catch (e) { if (g === this.gen) this.fresh.set({ loading: false, error: fail(e), data: [] }); }
  }

  async toggle(d: Dom) {
    d.open = !d.open; this.tops.update(t => ({ ...t, data: [...t.data] }));
    if (!d.open || d.subs || d.busy) return;
    d.busy = true;
    await this.ui.run(async () => {
      const r = await this.api.invoke(logsGroupedList, { client: this.ip(), hours: this.range(), by: 'name', domain: d.g.name, ordering: 'count', limit: 50 });
      d.subs = r.results;
    });
    d.busy = false; this.tops.update(t => ({ ...t, data: [...t.data] }));
  }

  // ---- ribbon: hover and keyboard share one selection, announced through the readout (aria-live) ----
  key(e: KeyboardEvent) {
    const n = this.ribbon().data.cells.length, w = this.range() === 168 ? 24 : 1, s = this.sel();
    const d = ({ ArrowRight: 1, ArrowLeft: -1, ArrowDown: w, ArrowUp: -w } as Record<string, number>)[e.key];
    if (d !== undefined) { e.preventDefault(); this.sel.set(Math.min(n - 1, Math.max(0, (s < 0 ? n - 1 : s + d)))); }
    else if (e.key === 'Escape') this.sel.set(-1);
  }
  alpha(c: Cell) { return c.count ? 12 + Math.round(88 * Math.sqrt(c.count / this.maxCount())) : 0; }
  label(c: Cell) {
    const t = new Date(c.start).toLocaleString([], { weekday: 'short', day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' });
    return `${t}: ${c.count} ${c.count === 1 ? 'query' : 'queries'}${c.count ? `, ${Math.round(c.blocked * 100 / c.count)}% blocked` : ''}`;
  }
  pct(g: QueryLogGroup) { return g.count ? Math.round(g.blocked * 100 / g.count) : 0; }

  block(name: string) {
    this.ui.ask(`Block ${name}?`, 'The domain and its subdomains will receive NXDOMAIN from the next query. Undo it in Blocklist > Personal blocks.', () =>
      this.ui.run(async () => { await this.api.invoke(blockedCreate, { body: { name } }); this.done.update(s => new Set(s).add(name)); }, { ok: `Blocked ${name}` }), 'Block domain');
  }
  allow(name: string) {
    this.ui.ask(`Allow ${name}?`, 'The name and its subdomains will not be blocked by the public lists. Remove the exception in Blocklist > Personal blocks.', () =>
      this.ui.run(async () => { await this.api.invoke(blockedCreate, { body: { name, allow: true } }); this.done.update(s => new Set(s).add(name)); }, { ok: `Allowed ${name}` }), 'Allow name');
  }
}
