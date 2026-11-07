import { DecimalPipe, NgTemplateOutlet } from '@angular/common';
import { Component, ElementRef, OnDestroy, inject, signal, viewChild } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { Api } from './api/api';
import { blockedCreate, logsAnswersList, logsGroupedList, logsList, logsPurgeCreate, logsResolvedList, geoIpsRetrieve } from './api/functions';
import { Answer, GeoIp, QueryLog, QueryLogGroup, Resolved } from './api/models';
import { countryName, flag } from './geo-util';
import { Ui } from './ui';

const PAGE = 50;
const SUB = 20; // individual queries loaded per expansion step

interface Sub { rows: QueryLog[]; count: number }
type Detail =
  | { kind: 'q'; row: QueryLog; answers: Answer[] | null }
  | { kind: 'g'; g: QueryLogGroup; level: number; resolved: Resolved[] | null };
interface Open { subs: QueryLogGroup[] | null; total: number; rows: QueryLog[]; count: number }

@Component({
  selector: 'app-logs-page',
  imports: [FormsModule, NgTemplateOutlet, RouterLink, DecimalPipe],
  template: `
    <header>
      <div>
        <h2>Query log</h2>
        <p class="soft">{{ grouped ? gCount() + ' domains' : count() + ' results' }}</p>
      </div>
      <div class="actions">
        <label class="live"><input type="checkbox" [(ngModel)]="grouped" name="grouped" (ngModelChange)="reset()"> Group by domain</label>
        <label class="live"><input type="checkbox" [(ngModel)]="live" name="live" (ngModelChange)="toggleLive()"> Refresh automatically</label>
        <button class="ghost" (click)="openPurge()">Purge log…</button>
      </div>
    </header>
    @if (notice()) { <p class="notice" role="status">{{ notice() }}</p> }

    <div class="composer filters">
      <input class="grow" type="search" name="q" [(ngModel)]="q" (ngModelChange)="search()" placeholder="Search by domain name" aria-label="Search by name">
      <select name="o" [(ngModel)]="outcome" (ngModelChange)="reset()" aria-label="Outcome">
        <option value="">All outcomes</option>
        <option value="local">Internal zones</option>
        <option value="forwarded">Forwarded</option>
        <option value="blocked">Blocked</option>
        <option value="error">Errors</option>
      </select>
      <select name="t" [(ngModel)]="type" (ngModelChange)="reset()" aria-label="Type">
        <option value="">All types</option>
        @for (t of types; track t) { <option>{{ t }}</option> }
      </select>
      <select name="rc" [(ngModel)]="rcode" (ngModelChange)="reset()" aria-label="Response code">
        <option value="">All responses</option>
        <option value="NOERROR">NOERROR</option>
        <option value="NXDOMAIN">NXDOMAIN</option>
        <option value="SERVFAIL">SERVFAIL</option>
        <option value="REFUSED">REFUSED</option>
      </select>
      <input class="ip" name="ans" [(ngModel)]="answer" (ngModelChange)="search()" placeholder="Search the answer (e.g. IP)" aria-label="Search the answer">
      <input class="ip" name="c" [(ngModel)]="client" (ngModelChange)="search()" placeholder="IP client" aria-label="IP client">
      <select name="h" [(ngModel)]="hours" (ngModelChange)="reset()" aria-label="Period">
        <option [ngValue]="1">Last hour</option>
        <option [ngValue]="24">Last 24 hours</option>
        <option [ngValue]="168">Last 7 days</option>
        <option [ngValue]="0">All time</option>
      </select>
      @if (grouped) {
        <select name="ord" [(ngModel)]="ordering" (ngModelChange)="reset()" aria-label="Order">
          <option value="last">Most recent</option>
          <option value="count">Most requested</option>
        </select>
      }
    </div>

    @if (grouped) {
      <ul class="records logs">
        @for (g of groups(); track g.name) {
          <ng-container *ngTemplateOutlet="grp; context: { $implicit: g, level: 0 }" />
          @if (domains()[g.name]; as d) {
            <li class="sub">
              @if (d.subs) {
                <ul class="records logs">
                  @for (s of d.subs; track s.name) {
                    <ng-container *ngTemplateOutlet="grp; context: { $implicit: s, level: 1 }" />
                    @if (names()[s.name]; as o) {
                      <li class="sub sub2">
                        <ul class="records logs">
                          @for (l of o.rows; track l.id) { <ng-container *ngTemplateOutlet="row; context: { $implicit: l, sub: true }" /> }
                        </ul>
                        @if (o.rows.length < o.count) {
                          <div class="more"><button class="ghost" (click)="moreOf(s.name)">Show more ({{ o.count - o.rows.length }})</button></div>
                        }
                      </li>
                    }
                  }
                </ul>
                @if (d.subs.length < d.total) {
                  <div class="more"><button class="ghost" (click)="moreSubs(g)">Show more subdomains ({{ d.total - d.subs.length }})</button></div>
                }
              } @else {
                <ul class="records logs">
                  @for (l of d.rows; track l.id) { <ng-container *ngTemplateOutlet="row; context: { $implicit: l, sub: true }" /> }
                </ul>
                @if (d.rows.length < d.count) {
                  <div class="more"><button class="ghost" (click)="moreDirect(g)">Show more ({{ d.count - d.rows.length }})</button></div>
                }
              }
            </li>
          }
        } @empty {
          <li class="empty">No queries match these filters.</li>
        }
      </ul>
      @if (groups().length < gCount()) { <div class="more"><button class="ghost" (click)="more()">Show more domains</button></div> }
    } @else {
      <ul class="records logs">
        @for (l of rows(); track l.id) { <ng-container *ngTemplateOutlet="row; context: { $implicit: l, sub: false }" /> }
        @empty { <li class="empty">No queries match these filters.</li> }
      </ul>
      @if (rows().length < count()) { <div class="more"><button class="ghost" (click)="more()">Show {{ PAGE }} more</button></div> }
    }

    <dialog #det class="confirm detail" (click)="$event.target === det ? det.close() : null">
      @if (detail(); as d) {
        @if (d.kind === 'q') {
          <h3><span class="type" [attr.data-t]="d.row.type">{{ d.row.type }}</span> {{ d.row.name }}</h3>
          <dl>
            <dt>Time</dt><dd>{{ time(d.row.time) }}</dd>
            <dt>Client</dt><dd class="mono">{{ d.row.client }}</dd>
            <dt>Outcome</dt><dd><span class="out" [attr.data-o]="d.row.outcome">{{ labels[d.row.outcome] }}</span></dd>
            <dt>Response code</dt><dd><span class="rc" [attr.data-rc]="d.row.rcode">{{ d.row.rcode }}</span></dd>
            <dt>Resolved by</dt><dd>{{ d.row.via || '—' }}</dd>
            <dt>Response time</dt><dd>{{ d.row.ms }} ms</dd>
            <dt>Main domain</dt><dd>{{ d.row.domain }}</dd>
          </dl>
          <h4>Records returned</h4>
          @if (d.answers; as list) {
            @if (list.length) {
              <table class="anstable">
                <thead><tr><th>Name</th><th>Type</th><th>Value</th><th>TTL</th><th>Location</th></tr></thead>
                <tbody>
                  @for (a of list; track $index) {
                    <tr><td class="mono">{{ a.name }}</td><td><span class="type" [attr.data-t]="a.type">{{ a.type }}</span></td><td class="mono">{{ a.value }}</td><td>{{ a.ttl }} s</td><td>{{ place(a.type, a.value) }}</td></tr>
                  }
                </tbody>
              </table>
            } @else {
              <p class="soft">{{ d.row.rcode === 'NOERROR' ? 'The answer is valid but has no records of this type.' : 'No records: the response is ' + d.row.rcode + '.' }}</p>
            }
          } @else { <p class="soft">Loading the answer…</p> }
        } @else {
          <h3>{{ d.g.name }}</h3>
          <dl>
            <dt>Query</dt><dd>{{ d.g.count }}</dd>
            @if (d.level === 0) { <dt>Distinct hosts</dt><dd>{{ d.g.names }}</dd> }
            <dt>Distinct clients</dt><dd>{{ d.g.clients }}</dd>
            <dt>Outcomes</dt>
            <dd class="mix">
              @if (d.g.local) { <span class="out sm" data-o="local">Internal {{ d.g.local }}</span> }
              @if (d.g.forwarded) { <span class="out sm" data-o="forwarded">Forwarded {{ d.g.forwarded }}</span> }
              @if (d.g.blocked) { <span class="out sm" data-o="blocked">Blocked {{ d.g.blocked }}</span> }
              @if (d.g.error) { <span class="out sm" data-o="error">Error {{ d.g.error }}</span> }
            </dd>
            <dt>Average time</dt><dd>{{ d.g.avg_ms | number: '1.0-0' }} ms</dd>
            <dt>Last request</dt><dd>{{ time(d.g.last) }}</dd>
          </dl>
          <h4>Recently resolved to</h4>
          @if (d.resolved; as list) {
            @if (list.length) {
              <table class="anstable">
                <thead><tr><th>Type</th><th>Value</th><th>Location</th></tr></thead>
                <tbody>@for (a of list; track $index) { <tr><td><span class="type" [attr.data-t]="a.type">{{ a.type }}</span></td><td class="mono">{{ a.value }}</td><td>{{ place(a.type, a.value) }}</td></tr> }</tbody>
              </table>
            } @else { <p class="soft">No address recorded for this group.</p> }
          } @else { <p class="soft">Loading addresses…</p> }
        }
      }
      <div class="actions"><button class="ghost" (click)="det.close()">Close</button></div>
    </dialog>

    <dialog #pg class="confirm" (click)="$event.target === pg ? pg.close() : null">
      <h3>Purge the log</h3>
      <p class="soft pl">Permanently deletes queries older than the chosen period. It applies to the whole log, not only the active filters.</p>
      <label class="field">
        <span class="lbl">Delete queries older than</span>
        <select name="ph" [(ngModel)]="purgeHours" (ngModelChange)="previewPurge()" aria-label="Period to keep">
          <option [ngValue]="24">1 day</option>
          <option [ngValue]="168">7 days</option>
          <option [ngValue]="720">30 days</option>
          <option [ngValue]="2160">90 days</option>
          <option [ngValue]="0">Everything: empty the log</option>
        </select>
        <small class="help">The daemon already deletes queries older than the days set in <code>QUERY_LOG_DAYS</code>.</small>
      </label>
      <p class="purgecount">@if (purgeCount() === null) { Counting queries… } @else { <b>{{ purgeCount() }}</b> queries will be deleted. This cannot be undone. }</p>
      @if (ui.error()) { <p class="error" role="alert">{{ ui.error() }}</p> }
      <div class="actions">
        <button class="ghost" (click)="pg.close()">Cancel</button>
        <button class="danger" (click)="doPurge()" [disabled]="!purgeCount()">Delete</button>
      </div>
    </dialog>

    <ng-template #grp let-g let-level="level">
      <li class="grp" [class.open]="isOpen(g.name, level)" [class.l1]="level === 1">
        <button class="chev" (click)="level === 0 ? toggleDomain(g) : toggleName(g)" [attr.aria-expanded]="isOpen(g.name, level)"
                [attr.aria-label]="(isOpen(g.name, level) ? 'Hide' : 'Show') + (level === 0 && g.names > 1 ? ' the subdomains of ' : ' the queries of ') + g.name">▸</button>
        <button class="rvalue linkish" (click)="level === 0 ? toggleDomain(g) : toggleName(g)">{{ g.name }}</button>
        @if (level === 0 && g.names > 1) { <span class="hosts" title="Distinct hosts queried">{{ g.names }} host</span> }
        <span class="mix">
          @if (g.local) { <span class="out sm" data-o="local" title="Internal zones">{{ g.local }}</span> }
          @if (g.forwarded) { <span class="out sm" data-o="forwarded" title="Forwarded">{{ g.forwarded }}</span> }
          @if (g.blocked) { <span class="out sm" data-o="blocked" title="Blocked">{{ g.blocked }}</span> }
          @if (g.error) { <span class="out sm" data-o="error" title="Errors">{{ g.error }}</span> }
        </span>
        <span class="ttlv wide"><b>{{ g.count }}</b> queries</span>
        <span class="ttlv wide">{{ g.clients }} client</span>
        <span class="when">{{ time(g.last) }}</span>
        @if (g.blocked < g.count) {
          <button class="mini" (click)="openGroup(g, level)" [attr.aria-label]="'Show the addresses of ' + g.name">Answer</button>
        }
        <a class="mini" routerLink="/audit" [queryParams]="{ domain: g.name }" [attr.aria-label]="'Analyse ' + g.name">Audit</a>
        @if (blockedNow().has(g.name)) {
          <span class="out sm" data-o="blocked">Blocked</span>
        } @else if (g.forwarded) {
          <button class="mini" (click)="block(g.name)" [attr.aria-label]="'Block ' + g.name"
                  [title]="level === 0 ? 'Block the domain and all its subdomains' : 'Block this host'">Block</button>
        }
      </li>
    </ng-template>

    <ng-template #row let-l let-sub="sub">
      <li [class.subrow]="sub">
        <span class="when">{{ time(l.time) }}</span>
        <span class="out" [attr.data-o]="l.outcome">{{ labels[l.outcome] }}</span>
        <span class="type" [attr.data-t]="l.type">{{ l.type }}</span>
        @if (!sub) { <button class="rvalue linkish" (click)="q = l.name; reset()" title="Filter by this name">{{ l.name }}</button> }
        @else { <span class="rvalue"></span> }
        <button class="ttlv linkish" (click)="client = l.client; reset()" title="Filter by this client">{{ l.client }}</button>
        <span class="ttlv">{{ l.ms }} ms</span>
        @if (l.rcode) {
          <button class="mini" (click)="openQuery(l)" [attr.aria-label]="'Show the answer of ' + l.name">Answer</button>
        }
        @if (!sub && l.outcome === 'forwarded') {
          @if (blockedNow().has(l.name)) { <span class="out sm" data-o="blocked">Blocked</span> }
          @else { <button class="mini" (click)="block(l.name)" [attr.aria-label]="'Block ' + l.name">Block</button> }
        }
      </li>
    </ng-template>`,
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
  q = ''; outcome = ''; type = ''; client = ''; rcode = ''; answer = ''; hours = 24; live = false;
  grouped = true; ordering: 'last' | 'count' = 'last';
  purgeHours = 168;
  purgeCount = signal<number | null>(null);
  private timer?: ReturnType<typeof setTimeout>;
  private poll?: ReturnType<typeof setInterval>;

  constructor() { this.reset(); }

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
    return { q: this.q || undefined, outcome: (this.outcome || undefined) as any, type: this.type || undefined, client: this.client || undefined, rcode: this.rcode || undefined, answer: this.answer || undefined, hours: this.hours || undefined };
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
