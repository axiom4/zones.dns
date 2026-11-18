import { DecimalPipe, NgTemplateOutlet } from '@angular/common';
import { Component, ElementRef, OnDestroy, computed, inject, signal, viewChild } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, ParamMap, Router, RouterLink, RouterLinkActive } from '@angular/router';
import { Api } from '../api/api';
import { blockedCreate, logsAnswersList, logsClientsList, logsGroupedList, logsList, logsPurgeCreate, logsResolvedList, geoIpsRetrieve, geoWhoisRetrieve } from '../api/functions';
import { Answer, GeoIp, QueryLog, QueryLogClient, QueryLogGroup, Resolved } from '../api/models';
import { Autocomplete } from '../lib/autocomplete';
import { InView } from '../lib/in-view';
import { countryName, flag } from '../lib/geo-util';
import { byIp } from '../lib/ip';
import { StepUp } from '../services/step-up';
import { Period } from '../services/period';
import { Ui } from '../services/ui';

const PAGE = 50;
const SUB = 20; // individual queries loaded per expansion step

interface Whois { ip: string; loading?: boolean; server?: string; text?: string; error?: string }
interface Sub { rows: QueryLog[]; count: number }
type Detail =
  | { kind: 'q'; row: QueryLog; answers: Answer[] | null }
  | { kind: 'g'; g: QueryLogGroup; level: number; resolved: Resolved[] | null };
interface Open { subs: QueryLogGroup[] | null; total: number; rows: QueryLog[]; count: number }

@Component({
  selector: 'app-logs-page',
  imports: [FormsModule, NgTemplateOutlet, RouterLink, RouterLinkActive, DecimalPipe, Autocomplete, InView],
  templateUrl: './logs-page.html',
})
export class LogsPage implements OnDestroy {
  private api = inject(Api);
  private stepUp = inject(StepUp);
  ui = inject(Ui);
  private route = inject(ActivatedRoute);
  private router = inject(Router);
  private periodStore = inject(Period);
  private pg = viewChild.required<ElementRef<HTMLDialogElement>>('pg');
  PAGE = PAGE;
  types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'PTR', 'SOA', 'SRV', 'TXT', 'HTTPS'];
  labels: { [k: string]: string } = { local: 'Internal', forwarded: 'Forwarded', blocked: 'Blocked', error: 'Error' };

  rows = signal<QueryLog[]>([]);
  count = signal(0);
  groups = signal<QueryLogGroup[]>([]);
  gCount = signal(0);
  // expanded main domains: sub-hosts when the domain has several, otherwise its log rows directly
  domains = signal<{ [domain: string]: Open }>({});
  // expanded hosts: their individual log rows
  names = signal<{ [name: string]: Sub }>({});
  q = ''; outcome = ''; type = ''; client = ''; rcode = ''; answer = ''; hours = 24; live = true;
  country = ''; // set by the link from the geolocation page
  asn = ''; // same, from the networks table

  grouped = false; ordering: 'last' | 'count' = 'last';
  purgeHours = 168;
  purgeCount = signal<number | null>(null);
  private timer?: ReturnType<typeof setTimeout>;
  private poll?: ReturnType<typeof setTimeout>;

  // distinct client IPs (with their name in the default zone) for the filter; refreshed when the list is opened and when the period changes
  clients = signal<QueryLogClient[]>([]);
  // sorted by address: IPv4 numerically, then IPv6 and anything else as text
  clientOptions = computed(() => this.clients().map(c => ({ value: c.ip, label: c.host })).sort((a, b) => byIp(a.value, b.value)));
  clientNames = signal<{ [ip: string]: string }>({});
  /** What was typed or picked, as an IP: a name of the default zone is looked up in the list. */
  private clientIp() { const c = this.client.trim().toLowerCase(); return c && this.clients().find(x => x.host === c || x.name === c)?.ip || this.client.trim(); }
  who(ip: string) { return this.clientNames()[ip] || ip; }
  async loadClients() {
    try {
      const r = await this.api.invoke(logsClientsList, { hours: this.hours || undefined });
      this.clients.set(r); this.clientNames.set(Object.fromEntries(r.filter(c => c.host).map(c => [c.ip, c.host])));
    } catch { /* the filter still works with the IP typed before: never an error */ }
  }

  constructor() {
    // Every filter lives in the URL (?q=&client=&outcome=&hours=...): links from Statistics and Geolocation land filtered, Back and reload keep it.
    this.route.queryParamMap.pipe(takeUntilDestroyed()).subscribe(p => this.fromUrl(p));
    this.loadClients(); this.toggleLive();
  }
  countryName = countryName;
  clearCountry() { this.country = ''; this.asn = ''; this.changed(); }

  /** The filters as query parameters: only what differs from the defaults. */
  private params() {
    const p: { [k: string]: string } = {};
    for (const k of ['q', 'outcome', 'type', 'client', 'rcode', 'answer', 'country', 'asn'] as const) if (this[k]) p[k] = this[k];
    if (this.hours !== 24) p['hours'] = String(this.hours);
    if (this.grouped) p['group'] = '1';
    if (this.grouped && this.ordering !== 'last') p['order'] = this.ordering;
    return p;
  }
  private shown = ''; // the filters of the rows on screen (as JSON of params()): a URL change that matches them is our own

  private fromUrl(p: ParamMap) {
    const s = (k: string) => (p.get(k) ?? '').trim();
    this.q = s('q'); this.type = s('type'); this.client = s('client'); this.answer = s('answer');
    this.outcome = ['local', 'forwarded', 'blocked', 'error'].includes(s('outcome')) ? s('outcome') : '';
    this.rcode = ['NOERROR', 'NXDOMAIN', 'SERVFAIL', 'REFUSED'].includes(s('rcode')) ? s('rcode') : '';
    this.country = s('country').toUpperCase(); this.asn = s('asn').toUpperCase();
    this.hours = p.has('hours') && [0, 1, 24, 168, 720].includes(Number(s('hours'))) ? Number(s('hours')) : this.periodStore.pick([0, 1, 24, 168, 720]);
    this.grouped = s('group') === '1'; this.ordering = s('order') === 'count' ? 'count' : 'last';
    const key = JSON.stringify(this.params());
    if (key === this.shown) return;
    this.shown = key; this.domains.set({}); this.names.set({}); this.reset();
  }

  /** A filter was changed on the page: write it to the URL (replacing the entry, so Back leaves the log) and reload. */
  changed() {
    this.periodStore.remember(this.hours);
    clearTimeout(this.timer);
    this.shown = JSON.stringify(this.params());
    this.router.navigate([], { queryParams: this.params(), replaceUrl: true });
    this.reset();
  }
  filterBy(k: 'q' | 'client', v: string) { this[k] = v; this.changed(); }

  // ---- popup with the details of a query / group, fetched only when it is opened ----
  detail = signal<Detail | null>(null);
  private geo = signal<{ [ip: string]: GeoIp }>({});
  private det = viewChild.required<ElementRef<HTMLDialogElement>>('det');

  /** Where an address is: asked after the popup is open, so it never delays it. */
  private async loadGeo(items: { type: string; value: string }[]) {
    const ips = [...new Set(items.filter(a => a.type === 'A' || a.type === 'AAAA').map(a => a.value))].slice(0, 50);
    if (!ips.length) return;
    try {
      const r = await this.api.invoke(geoIpsRetrieve, { ips: ips.join(',') });
      this.geo.update(g => ({ ...g, ...Object.fromEntries(r.results.map(x => [x.ip, x])) }));
    } catch { /* the position is a nicety: never an error */ }
  }

  whois = signal<Whois | null>(null);
  canWhois(type: string, ip: string) { return (type === 'A' || type === 'AAAA') && !this.geo()[ip]?.private; }
  async lookupWhois(ip: string) {
    this.whois.set({ ip, loading: true });
    try {
      const r = await this.api.invoke(geoWhoisRetrieve, { ip });
      this.whois.set({ ip, server: r.server, text: r.text });
    } catch (e: any) {
      this.whois.set({ ip, error: e?.error?.ip?.[0] ?? e?.error?.detail ?? `The WHOIS lookup failed (HTTP ${e?.status ?? 'no answer'}).` });
    }
  }

  place(type: string, ip: string) {
    if (type !== 'A' && type !== 'AAAA') return '';
    const g = this.geo()[ip];
    if (!g) return '…';
    if (g.private) return `${flag('PRIV')} Internal network`;
    return g.country ? `${flag(g.country)} ${countryName(g.country)}${g.asn ? ' · ' + g.asn : ''}` : `${flag('??')} Unknown`;
  }

  openQuery(row: QueryLog) {
    this.whois.set(null);
    this.detail.set({ kind: 'q', row, answers: null });
    this.det().nativeElement.showModal(); this.dialogOpen.set(true);
    return this.ui.run(async () => {
      const r = await this.api.invoke(logsAnswersList, { ids: String(row.id) });
      this.detail.update(d => (d?.kind === 'q' && d.row.id === row.id ? { ...d, answers: r[0]?.answers ?? [] } : d));
      this.loadGeo(r[0]?.answers ?? []);
    });
  }

  openGroup(g: QueryLogGroup, level: number) {
    this.whois.set(null);
    this.detail.set({ kind: 'g', g, level, resolved: null });
    this.det().nativeElement.showModal(); this.dialogOpen.set(true);
    return this.ui.run(async () => {
      const r = await this.api.invoke(logsResolvedList, { by: level === 0 ? 'domain' : 'name', names: g.name });
      this.detail.update(d => (d?.kind === 'g' && d.g.name === g.name ? { ...d, resolved: r[0]?.resolved ?? [] } : d));
      this.loadGeo(r[0]?.resolved ?? []);
    });
  }

  private destroyed = false;
  ngOnDestroy() { this.destroyed = true; clearTimeout(this.timer); clearTimeout(this.poll); }

  time(iso: string) { return new Date(iso).toLocaleString([], { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' }); }
  isOpen(name: string, level: number) { return name in (level === 0 ? this.domains() : this.names()); }

  // Debounce typing so each keystroke doesn't hit the API.
  search() { clearTimeout(this.timer); this.timer = setTimeout(() => this.changed(), 250); }

  private filters() {
    return { q: this.q || undefined, outcome: (this.outcome || undefined) as any, type: this.type || undefined, client: this.clientIp() || undefined, rcode: this.rcode || undefined, answer: this.answer || undefined, hours: this.hours || undefined, country: this.country || undefined, asn: this.asn || undefined };
  }

  /** Reload from the start. While live, keep as many rows as were already loaded so the list doesn't jump. */
  reset(silent = false) {
    return this.ui.run(async () => {
      if (this.grouped) {
        const limit = Math.max(PAGE, this.live ? this.groups().length : 0);
        const r = await this.api.invoke(logsGroupedList, { ...this.filters(), by: 'domain', ordering: this.ordering, limit, offset: 0 });
        this.groups.set(r.results); this.gCount.set(r.count); this.rows.set([]);
        // refresh what is expanded; drop what no longer matches the filters
        const oldDomains = this.domains(), oldNames = this.names();
        const nextDomains: { [d: string]: Open } = {}, nextNames: { [n: string]: Sub } = {};
        await Promise.all(r.results.filter(g => g.name in oldDomains).map(async g => {
          const cur = oldDomains[g.name];
          nextDomains[g.name] = await this.fetchDomain(g, Math.max(PAGE, cur.subs?.length ?? 0), Math.max(SUB, cur.rows.length));
        }));
        const subNames = Object.values(nextDomains).flatMap(d => d.subs?.map(s => s.name) ?? []);
        await Promise.all(subNames.filter(n => n in oldNames).map(async n => { nextNames[n] = await this.fetchSub(n, 0, Math.max(SUB, oldNames[n].rows.length)); }));
        this.domains.set(nextDomains); this.names.set(nextNames);
      } else {
        const r = await this.api.invoke(logsList, { ...this.filters(), limit: Math.max(PAGE, this.live ? this.rows().length : 0), offset: 0 });
        this.rows.set(r.results); this.count.set(r.count); this.groups.set([]);
      }
      this.fresh.set(0);
    }, { silent });
  }

  private paging = false; // a page is on its way: the scroll must not ask for the same one twice
  async more() {
    if (this.paging) return;
    this.paging = true;
    try { await this.page(); } finally { this.paging = false; }
  }
  private page() {
    return this.ui.run(async () => {
      if (this.grouped) {
        const r = await this.api.invoke(logsGroupedList, { ...this.filters(), by: 'domain', ordering: this.ordering, limit: PAGE, offset: this.groups().length });
        this.groups.update(x => [...x, ...r.results]); this.gCount.set(r.count);
      } else {
        const r = await this.api.invoke(logsList, { ...this.filters(), limit: PAGE, before: this.rows().at(-1)?.id });
        this.rows.update(x => [...x, ...r.results]); this.count.set(r.count);
      }
    });
  }

  /** before: id of the last row already shown (keyset: rows logged meanwhile do not shift the next page). */
  private async fetchSub(name: string, before: number | undefined, limit: number) {
    const r = await this.api.invoke(logsList, { ...this.filters(), q: undefined, name, limit, before });
    return { rows: r.results, count: r.count };
  }

  /** A domain with several hosts opens to its sub-hosts; a single-host domain opens straight to its queries. */
  private async fetchDomain(g: { name: string; names: number }, subLimit = PAGE, rowLimit = SUB): Promise<Open> {
    if (g.names > 1) {
      const r = await this.api.invoke(logsGroupedList, { ...this.filters(), q: undefined, by: 'name', domain: g.name, ordering: this.ordering, limit: subLimit, offset: 0 });
      return { subs: r.results, total: r.count, rows: [], count: 0 };
    }
    const r = await this.api.invoke(logsList, { ...this.filters(), q: undefined, domain: g.name, limit: rowLimit, offset: 0 });
    return { subs: null, total: 0, rows: r.results, count: r.count };
  }

  toggleDomain(g: QueryLogGroup) {
    if (this.isOpen(g.name, 0)) {
      this.domains.update(o => { const { [g.name]: _, ...rest } = o; return rest; });
      return;
    }
    return this.ui.run(async () => { const d = await this.fetchDomain(g); this.domains.update(o => ({ ...o, [g.name]: d })); });
  }

  toggleName(g: QueryLogGroup) {
    if (this.isOpen(g.name, 1)) {
      this.names.update(o => { const { [g.name]: _, ...rest } = o; return rest; });
      return;
    }
    return this.ui.run(async () => { const s = await this.fetchSub(g.name, undefined, SUB); this.names.update(o => ({ ...o, [g.name]: s })); });
  }

  moreSubs(g: QueryLogGroup) {
    return this.ui.run(async () => {
      const cur = this.domains()[g.name];
      const r = await this.api.invoke(logsGroupedList, { ...this.filters(), q: undefined, by: 'name', domain: g.name, ordering: this.ordering, limit: PAGE, offset: cur.subs!.length });
      this.domains.update(o => ({ ...o, [g.name]: { ...cur, subs: [...cur.subs!, ...r.results], total: r.count } }));
    });
  }

  moreDirect(g: QueryLogGroup) {
    return this.ui.run(async () => {
      const cur = this.domains()[g.name];
      const r = await this.api.invoke(logsList, { ...this.filters(), q: undefined, domain: g.name, limit: SUB, before: cur.rows.at(-1)?.id });
      this.domains.update(o => ({ ...o, [g.name]: { ...cur, rows: [...cur.rows, ...r.results], count: r.count } }));
    });
  }

  moreOf(name: string) {
    return this.ui.run(async () => {
      const cur = this.names()[name];
      const s = await this.fetchSub(name, cur.rows.at(-1)?.id, SUB);
      this.names.update(o => ({ ...o, [name]: { rows: [...cur.rows, ...s.rows], count: s.count } }));
    });
  }

  openPurge() { this.pg().nativeElement.showModal(); this.dialogOpen.set(true); this.previewPurge(); }

  previewPurge() {
    this.purgeCount.set(null);
    return this.ui.run(async () => {
      const r = await this.api.invoke(logsPurgeCreate, { body: { older_than_hours: this.purgeHours, dry_run: true } });
      this.purgeCount.set(r.count);
    });
  }

  doPurge() {
    const dlg = this.pg().nativeElement;
    return this.ui.run(async () => {
      dlg.close(); // no modal over a modal: the second factor is asked on its own
      try {
        const grant = await this.stepUp.request('log-purge', `Delete ${this.purgeCount() ?? 0} queries from the log`, 'Delete queries'); // the history is erased only by whoever proves a second factor
        if (grant === null) { dlg.showModal(); return; }
        await this.api.invoke(logsPurgeCreate, { body: { older_than_hours: this.purgeHours, dry_run: false }, 'X-MFA-Grant': grant || undefined });
      } catch (e) { dlg.showModal(); throw e; } // the error is shown in the dialog
      this.domains.set({}); this.names.set({});
      await this.reset();
    }, { ok: `Deleted ${this.purgeCount() ?? 0} queries from the log` });
  }

  toggleLive() {
    clearTimeout(this.poll);
    if (this.live) this.refresh(3000);
  }

  /** Live refresh: one request at a time (a slow one used to be overtaken by the next, and they piled up on the server), nothing while the tab is
   * hidden, and the wait grows with the time the last refresh took (at least 3 s, three times as long as the request). */
  private refresh(delay: number) {
    this.poll = setTimeout(async () => {
      let next = delay;
      if (!document.hidden) {
        const t = Date.now();
        await (this.busy() ? this.peek() : this.reset(true));
        next = Math.max(3000, 3 * (Date.now() - t));
      }
      if (this.live && !this.destroyed) this.refresh(next); // a refresh still running when the page was left must not start the loop again
    }, delay);
  }

  // ---- live mode: it holds still while the user points at, or works in, the list (rows moving under the cursor caused wrong clicks) ----
  private hover = signal(false);
  focusIn = signal(false);
  private dialogOpen = signal(false);
  busy = computed(() => this.hover() || this.focusIn() || this.dialogOpen());
  fresh = signal(0); // newer rows seen while paused (flat list); -1: something changed (grouped view)
  point(on: boolean, e?: PointerEvent) { if (!e || e.pointerType === 'mouse') this.hover.set(on); }
  focusOut(e: FocusEvent) { if (!(e.currentTarget as HTMLElement).contains(e.relatedTarget as Node)) this.focusIn.set(false); }
  dialogClosed() { this.dialogOpen.set(false); }

  /** While paused: only count what is new, without touching the rows on screen. */
  private peek() {
    return this.ui.run(async () => {
      if (this.grouped) {
        const r = await this.api.invoke(logsGroupedList, { ...this.filters(), by: 'domain', ordering: this.ordering, limit: 1, offset: 0 });
        if (r.results[0] && (r.results[0].last !== this.groups()[0]?.last || r.count !== this.gCount())) this.fresh.set(-1);
      } else {
        const top = this.rows()[0]?.id ?? 0;
        const r = await this.api.invoke(logsList, { ...this.filters(), limit: PAGE, offset: 0 });
        this.fresh.set(r.results.filter(x => x.id > top).length);
      }
    }, { silent: true }); // shortcut: errors are swallowed by silent; the 401 interceptor and the next refresh cover them
  }
  showFresh() { this.reset(); window.scrollTo({ top: 0 }); }

  blockedNow = signal<ReadonlySet<string>>(new Set()); // blocked in this session: the log rows are history and keep their old outcome
  allowedNow = signal<ReadonlySet<string>>(new Set()); // same, for names allowed here

  /** Why a blocked query was blocked, in words (the daemon logs the rule in `via`). */
  why(l: QueryLog) {
    const v = l.via ?? '';
    if (!v) return 'Blocked (the rule was not recorded)';
    if (v === 'rate limit') return 'Blocked: this client sent too many queries (rate limit)';
    const m = /^blacklist (\S+) \((.+)\)$/.exec(v);
    if (m) return m[1] === l.name ? `Blocked by the list ${m[2]}` : `Blocked by the list ${m[2]} (entry ${m[1]})`;
    const c = /^cname (\S+) -> blacklist (\S+) \((.+)\)$/.exec(v);
    if (c) return `Blocked: its alias ${c[1]} is on the list ${c[3]}`;
    if (v.startsWith('suspicious: ')) return 'Blocked as suspicious: ' + v.slice(12);
    return 'Blocked: ' + v;
  }
  /** An exception helps unless the block was the rate limit. */
  canAllow(l: QueryLog) { return l.outcome === 'blocked' && l.via !== 'rate limit'; }

  block(name: string) {
    this.ui.ask(`Block ${name}?`, 'The domain and its subdomains will receive NXDOMAIN from the next query. Rows already in the log keep their outcome. Undo it in Blocklist > Personal blocks.', () =>
      this.ui.run(async () => {
        await this.api.invoke(blockedCreate, { body: { name } });
        this.blockedNow.set(new Set([...this.blockedNow(), name]));
      }, { ok: `Blocked ${name}` }), 'Block domain');
  }

  allow(name: string) {
    this.ui.ask(`Allow ${name}?`, 'The name and its subdomains will never be blocked by the public lists (a longer personal block still wins). Rows already in the log keep their outcome. Remove the exception in Blocklist > Personal blocks.', () =>
      this.ui.run(async () => {
        await this.api.invoke(blockedCreate, { body: { name, allow: true } });
        this.allowedNow.set(new Set([...this.allowedNow(), name]));
        this.det().nativeElement.close();
      }, { ok: `Allowed ${name}` }), 'Allow name');
  }
}
