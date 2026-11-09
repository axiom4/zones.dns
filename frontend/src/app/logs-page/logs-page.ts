import { DecimalPipe, NgTemplateOutlet } from '@angular/common';
import { Component, ElementRef, OnDestroy, computed, inject, signal, viewChild } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { Api } from '../api/api';
import { blockedCreate, logsAnswersList, logsClientsList, logsGroupedList, logsList, logsPurgeCreate, logsResolvedList, geoIpsRetrieve } from '../api/functions';
import { Answer, GeoIp, QueryLog, QueryLogClient, QueryLogGroup, Resolved } from '../api/models';
import { Autocomplete } from '../lib/autocomplete';
import { countryName, flag } from '../lib/geo-util';
import { Ui } from '../services/ui';

/** Sort key of an address: IPv4 as 4 zero-padded numbers, ahead of everything else. */
const ipKey = (ip: string) => /^\d+(\.\d+){3}$/.test(ip) ? '0' + ip.split('.').map(n => n.padStart(3, '0')).join('.') : '1' + ip;

const PAGE = 50;
const SUB = 20; // individual queries loaded per expansion step

interface Sub { rows: QueryLog[]; count: number }
type Detail =
  | { kind: 'q'; row: QueryLog; answers: Answer[] | null }
  | { kind: 'g'; g: QueryLogGroup; level: number; resolved: Resolved[] | null };
interface Open { subs: QueryLogGroup[] | null; total: number; rows: QueryLog[]; count: number }

@Component({
  selector: 'app-logs-page',
  imports: [FormsModule, NgTemplateOutlet, RouterLink, DecimalPipe, Autocomplete],
  templateUrl: './logs-page.html',
})
export class LogsPage implements OnDestroy {
  private api = inject(Api);
  ui = inject(Ui);
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
  grouped = false; ordering: 'last' | 'count' = 'last';
  purgeHours = 168;
  purgeCount = signal<number | null>(null);
  private timer?: ReturnType<typeof setTimeout>;
  private poll?: ReturnType<typeof setInterval>;

  // distinct client IPs (with their name in the default zone) for the filter; refreshed when the list is opened and when the period changes
  clients = signal<QueryLogClient[]>([]);
  // sorted by address: IPv4 numerically, then IPv6 and anything else as text
  clientOptions = computed(() => this.clients().map(c => ({ value: c.ip, label: c.host })).sort((a, b) => ipKey(a.value).localeCompare(ipKey(b.value))));
  clientNames = signal<{ [ip: string]: string }>({});
  /** What was typed or picked, as an IP: a name of the default zone is looked up in the list. */
  private clientIp() { const c = this.client.trim().toLowerCase(); return this.clients().find(x => x.host === c || x.name === c)?.ip ?? this.client.trim(); }
  who(ip: string) { return this.clientNames()[ip] || ip; }
  async loadClients() {
    try {
      const r = await this.api.invoke(logsClientsList, { hours: this.hours || undefined });
      this.clients.set(r); this.clientNames.set(Object.fromEntries(r.filter(c => c.name).map(c => [c.ip, c.name])));
    } catch { /* the filter still works with the IP typed before: never an error */ }
  }

  constructor() { this.reset(); this.loadClients(); this.toggleLive(); }

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

  place(type: string, ip: string) {
    if (type !== 'A' && type !== 'AAAA') return '';
    const g = this.geo()[ip];
    if (!g) return '…';
    if (g.private) return `${flag('PRIV')} Internal network`;
    return g.country ? `${flag(g.country)} ${countryName(g.country)}${g.asn ? ' · ' + g.asn : ''}` : `${flag('??')} Unknown`;
  }

  openQuery(row: QueryLog) {
    this.detail.set({ kind: 'q', row, answers: null });
    this.det().nativeElement.showModal();
    return this.ui.run(async () => {
      const r = await this.api.invoke(logsAnswersList, { ids: String(row.id) });
      this.detail.update(d => (d?.kind === 'q' && d.row.id === row.id ? { ...d, answers: r[0]?.answers ?? [] } : d));
      this.loadGeo(r[0]?.answers ?? []);
    });
  }

  openGroup(g: QueryLogGroup, level: number) {
    this.detail.set({ kind: 'g', g, level, resolved: null });
    this.det().nativeElement.showModal();
    return this.ui.run(async () => {
      const r = await this.api.invoke(logsResolvedList, { by: level === 0 ? 'domain' : 'name', names: g.name });
      this.detail.update(d => (d?.kind === 'g' && d.g.name === g.name ? { ...d, resolved: r[0]?.resolved ?? [] } : d));
      this.loadGeo(r[0]?.resolved ?? []);
    });
  }

  ngOnDestroy() { clearTimeout(this.timer); clearInterval(this.poll); }

  time(iso: string) { return new Date(iso).toLocaleString([], { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' }); }
  isOpen(name: string, level: number) { return name in (level === 0 ? this.domains() : this.names()); }

  // Debounce typing so each keystroke doesn't hit the API.
  search() { clearTimeout(this.timer); this.timer = setTimeout(() => this.reset(), 250); }

  private filters() {
    return { q: this.q || undefined, outcome: (this.outcome || undefined) as any, type: this.type || undefined, client: this.clientIp() || undefined, rcode: this.rcode || undefined, answer: this.answer || undefined, hours: this.hours || undefined };
  }

  /** Reload from the start. While live, keep as many rows as were already loaded so the list doesn't jump. */
  reset() {
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
    });
  }

  more() {
    return this.ui.run(async () => {
      if (this.grouped) {
        const r = await this.api.invoke(logsGroupedList, { ...this.filters(), by: 'domain', ordering: this.ordering, limit: PAGE, offset: this.groups().length });
        this.groups.update(x => [...x, ...r.results]); this.gCount.set(r.count);
      } else {
        const r = await this.api.invoke(logsList, { ...this.filters(), limit: PAGE, offset: this.rows().length });
        this.rows.update(x => [...x, ...r.results]); this.count.set(r.count);
      }
    });
  }

  private async fetchSub(name: string, offset: number, limit: number) {
    const r = await this.api.invoke(logsList, { ...this.filters(), q: undefined, name, limit, offset });
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
    return this.ui.run(async () => { const s = await this.fetchSub(g.name, 0, SUB); this.names.update(o => ({ ...o, [g.name]: s })); });
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
      const r = await this.api.invoke(logsList, { ...this.filters(), q: undefined, domain: g.name, limit: SUB, offset: cur.rows.length });
      this.domains.update(o => ({ ...o, [g.name]: { ...cur, rows: [...cur.rows, ...r.results], count: r.count } }));
    });
  }

  moreOf(name: string) {
    return this.ui.run(async () => {
      const cur = this.names()[name];
      const s = await this.fetchSub(name, cur.rows.length, SUB);
      this.names.update(o => ({ ...o, [name]: { rows: [...cur.rows, ...s.rows], count: s.count } }));
    });
  }

  openPurge() { this.ui.error.set(''); this.pg().nativeElement.showModal(); this.previewPurge(); }

  previewPurge() {
    this.purgeCount.set(null);
    return this.ui.run(async () => {
      const r = await this.api.invoke(logsPurgeCreate, { body: { older_than_hours: this.purgeHours, dry_run: true } });
      this.purgeCount.set(r.count);
    });
  }

  doPurge() {
    return this.ui.run(async () => {
      await this.api.invoke(logsPurgeCreate, { body: { older_than_hours: this.purgeHours, dry_run: false } });
      this.pg().nativeElement.close();
      this.domains.set({}); this.names.set({});
      await this.reset();
    });
  }

  toggleLive() {
    clearInterval(this.poll);
    if (this.live) this.poll = setInterval(() => this.reset(), 3000);
  }

  notice = signal('');
  blockedNow = signal<ReadonlySet<string>>(new Set()); // blocked in this session: the log rows are history and keep their old outcome

  block(name: string) {
    this.ui.ask(`Block ${name}?`, 'The domain and its subdomains will receive NXDOMAIN. You can unblock it from Blacklist > Personal blocks.', () =>
      this.ui.run(async () => {
        await this.api.invoke(blockedCreate, { body: { name } });
        this.blockedNow.set(new Set([...this.blockedNow(), name]));
        this.notice.set(`${name} blocked: from the next query it answers NXDOMAIN. The log rows stay as they were.`);
      }));
  }
}
