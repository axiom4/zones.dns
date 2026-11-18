/**
 * Command palette (Ctrl/Cmd+K). Standalone component + PaletteService.
 *
 * WIRING (two lines, nothing else; no route needed):
 *   shell.ts   : import { CommandPalette } from '../command-palette/command-palette';   and add CommandPalette to `imports: [...]`
 *   shell.html : <app-command-palette />      (anywhere, e.g. last line; it renders a <dialog> in the top layer)
 * The Ctrl/Cmd+K listener is registered once, when the service is first injected (the component does it).
 * Optional: inject(PaletteService).open() from a button; register({ id, title, run }) adds commands (returns an unregister fn).
 * Prefixes: `>` actions, `@` devices/hosts, `/` pages. Domain-looking input adds Check / Block / Allow / Show queries.
 */
import { Component, ElementRef, Injectable, computed, effect, inject, signal, viewChild } from '@angular/core';
import { Router } from '@angular/router';
import { Api } from '../api/api';
import { blockedCreate, blockedDestroy, blockedSuggestionsList, dhcpLeasesList, hostsList, recordsList, zonesList } from '../api/functions';
import { Ui } from '../services/ui';

export type Kind = 'page' | 'zone' | 'record' | 'host' | 'device' | 'blocked' | 'action';
type Act = { nav: unknown[]; q?: Record<string, string> } | { block: string } | { allow: string } | { fn: () => unknown };
export interface PaletteItem { id: string; kind: Kind; title: string; sub?: string; keywords?: string; act: Act }
export interface PaletteCommand { id: string; title: string; sub?: string; keywords?: string; run: () => unknown }
interface Hit { item: PaletteItem; idx: number[]; score: number }

const KIND: Record<Kind, { label: string; glyph: string; color: string }> = {
  page: { label: 'Page', glyph: '↗', color: 'var(--brand)' },
  zone: { label: 'Zone', glyph: 'Z', color: 'var(--c-prx)' },
  record: { label: 'Record', glyph: 'R', color: 'var(--c-prx)' },
  host: { label: 'Host', glyph: 'H', color: 'var(--c-prx)' },
  device: { label: 'Device', glyph: 'D', color: 'var(--warn)' },
  blocked: { label: 'Blocked', glyph: '⊘', color: 'var(--danger)' },
  action: { label: 'Action', glyph: '›', color: 'var(--ok)' },
};
const PAGES: { title: string; nav: string[]; kw: string }[] = [
  { title: 'Zones', nav: ['/zones'], kw: 'dns records' },
  { title: 'Static hosts', nav: ['/zones/hosts'], kw: 'hosts a record address' },
  { title: 'Devices: leases', nav: ['/dhcp/leases'], kw: 'dhcp clients' },
  { title: 'Devices: reservations', nav: ['/dhcp/reservations'], kw: 'dhcp fixed ip' },
  { title: 'Devices: settings', nav: ['/dhcp/settings'], kw: 'dhcp scope' },
  { title: 'Blocklist: my blocks', nav: ['/blacklist/manual'], kw: 'block allow exceptions' },
  { title: 'Blocklist: lists', nav: ['/blacklist/lists'], kw: 'sources subscriptions' },
  { title: 'DNS log', nav: ['/logs/dns'], kw: 'queries history' },
  { title: 'Proxy log', nav: ['/logs/proxy'], kw: 'requests' },
  { title: 'Proxy settings', nav: ['/proxy/settings'], kw: 'https filter ca' },
  { title: 'Statistics', nav: ['/stats'], kw: 'charts top' },
  { title: 'Traffic map', nav: ['/geo'], kw: 'geolocation countries' },
  { title: 'Domain check', nav: ['/audit'], kw: 'audit dnssec mail' },
  { title: 'Security', nav: ['/security'], kw: 'mfa passkey totp password' },
];
const DOMAIN = /^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z][a-z0-9-]{0,62}$/i;
const TTL = 60_000, RECENT_KEY = 'palette.recent', MAX_SHOWN = 40;

/** Tiny fuzzy scorer: all space-separated tokens must match. Substring beats subsequence; word starts and runs score extra. */
export function fuzzy(query: string, text: string): { score: number; idx: number[] } | null {
  const t = text.toLowerCase(); let total = 0; const idx: number[] = [];
  for (const tok of query.toLowerCase().split(/\s+/).filter(Boolean)) {
    const at = t.indexOf(tok);
    if (at >= 0) {
      total += 100 + tok.length * 4 - Math.min(at, 40) + (at === 0 || /[\s.\-_:/@]/.test(t[at - 1]) ? 30 : 0);
      for (let i = 0; i < tok.length; i++) idx.push(at + i);
      continue;
    }
    let p = 0, run = 0, s = 0; const hit: number[] = [];
    for (const ch of tok) {
      const j = t.indexOf(ch, p);
      if (j < 0) return null;
      run = j === p && hit.length ? run + 1 : 0;
      s += 10 + run * 6 + (j === 0 || /[\s.\-_:/@]/.test(t[j - 1]) ? 8 : 0) - Math.min(j - p, 10);
      hit.push(j); p = j + 1;
    }
    total += s; idx.push(...hit);
  }
  return { score: total, idx: [...new Set(idx)].sort((a, b) => a - b) };
}

@Injectable({ providedIn: 'root' })
export class PaletteService {
  readonly isOpen = signal(false);
  readonly commands = signal<PaletteCommand[]>([]);

  constructor() {
    // one listener for the whole session: a root service is built once
    document.addEventListener('keydown', e => {
      if ((e.ctrlKey || e.metaKey) && !e.altKey && !e.shiftKey && e.key.toLowerCase() === 'k') { e.preventDefault(); this.toggle(); }
    });
  }
  open() { this.isOpen.set(true); }
  close() { this.isOpen.set(false); }
  toggle() { this.isOpen.update(v => !v); }
  register(c: PaletteCommand) {
    this.commands.update(l => [...l.filter(x => x.id !== c.id), c]);
    return () => this.commands.update(l => l.filter(x => x !== c));
  }
}

@Component({
  selector: 'app-command-palette',
  template: `
    <dialog #dlg class="cp" aria-label="Command palette" (close)="palette.close()" (cancel)="palette.close()"
            (click)="$event.target === dlg ? palette.close() : null" (keydown)="keys($event)">
      <div class="bar">
        <span class="mode" [class.on]="mode().label" aria-hidden="true">{{ mode().label || 'Go to' }}</span>
        <input #inp type="text" role="combobox" aria-autocomplete="list" aria-haspopup="listbox" aria-label="Search pages, zones, devices, domains"
               aria-controls="cp-list" [attr.aria-expanded]="hits().length > 0" [attr.aria-activedescendant]="hits().length ? 'cp-o' + sel() : null"
               placeholder="Search or type a domain…   > actions   @ devices   / pages" autocomplete="off" spellcheck="false" autocapitalize="off"
               [value]="raw()" (input)="typed($any($event.target).value)">
        <kbd>Esc</kbd>
      </div>
      <div class="body">
        @if (state() === 'loading' && !hits().length) { <p class="empty" role="status"><span class="pulse"></span>Loading zones, devices and blocked domains…</p> }
        @if (state() === 'error') { <p class="empty err" role="alert">Some data could not be loaded.
          <button type="button" (click)="load(true)">Retry</button></p> }
        <ul id="cp-list" role="listbox" aria-label="Results" [hidden]="!hits().length">
          @for (h of hits(); track h.item.id; let i = $index) {
            <li role="option" [id]="'cp-o' + i" [attr.aria-selected]="i === sel()" [class.sel]="i === sel()" [style.--k]="kinds[h.item.kind].color"
                (mousemove)="sel.set(i)" (click)="run(h.item)">
              <span class="tile" aria-hidden="true">{{ kinds[h.item.kind].glyph }}</span>
              <span class="txt">
                <span class="t">@for (p of parts(h); track $index) { @if (p.m) { <mark>{{ p.s }}</mark> } @else { {{ p.s }} } }</span>
                @if (h.item.sub) { <span class="s">{{ h.item.sub }}</span> }
              </span>
              <span class="kind">{{ kinds[h.item.kind].label }}</span>
              <kbd class="ret" aria-hidden="true">↵</kbd>
            </li>
          }
        </ul>
        @if (!hits().length && state() !== 'loading' && state() !== 'error') {
          <p class="empty" role="status">{{ query() ? 'Nothing matches “' + query() + '”.' : 'Nothing here yet.' }}</p>
        }
        <p class="sr" aria-live="polite">{{ hits().length }} results</p>
      </div>
      <footer aria-hidden="true">
        <span><kbd>↑</kbd><kbd>↓</kbd> move</span><span><kbd>↵</kbd> open</span><span><kbd>&gt;</kbd> actions</span><span><kbd>&#64;</kbd> devices</span><span><kbd>/</kbd> pages</span>
      </footer>
    </dialog>`,
  styles: `
    :host { display: contents; }
    dialog.cp { position: fixed; inset: 12vh auto auto 50%; transform: translateX(-50%); margin: 0; padding: 0; width: min(640px, calc(100vw - 1.5rem));
      max-height: min(70vh, 34rem); display: none; flex-direction: column; background: var(--raised); color: var(--ink); border: 0; border-radius: 14px; box-shadow: var(--shadow-pop); overflow: hidden; }
    dialog.cp[open] { display: flex; }
    dialog.cp::backdrop { background: color-mix(in srgb, #0b1420 45%, transparent); backdrop-filter: blur(2px); }
    @media (prefers-reduced-motion: no-preference) {
      dialog.cp[open] { animation: cp-in .14s cubic-bezier(.2, .8, .3, 1); }
      dialog.cp[open]::backdrop { animation: cp-fade .14s ease-out; }
      .pulse { animation: cp-pulse 1s ease-in-out infinite; }
    }
    @keyframes cp-in { from { opacity: 0; transform: translateX(-50%) translateY(-8px) scale(.985); } }
    @keyframes cp-fade { from { opacity: 0; } }
    @keyframes cp-pulse { 50% { opacity: .35; } }
    .bar { display: flex; align-items: center; gap: .65rem; padding: .7rem .85rem; border-bottom: 1px solid var(--line-soft); background: var(--surface); }
    .mode { flex: none; font: 700 11px var(--mono); letter-spacing: .06em; text-transform: uppercase; color: var(--muted); border: 1px solid var(--line-soft); border-radius: 999px; padding: .22rem .6rem; }
    .mode.on { color: var(--brand-ink); background: var(--brand); border-color: var(--brand); }
    .bar input { flex: 1; border: 0; background: transparent; padding: .35rem 0; font-size: 1.05rem; outline: none; min-width: 0; }
    .bar input:focus { outline: none; }
    kbd { font: 600 11px var(--mono); color: var(--muted); background: var(--sunk); border: 1px solid var(--line-soft); border-bottom-width: 2px; border-radius: 5px; padding: .08rem .38rem; }
    .body { overflow-y: auto; overscroll-behavior: contain; padding: .35rem; min-height: 3rem; }
    ul { list-style: none; margin: 0; padding: 0; display: grid; gap: 1px; }
    li { display: grid; grid-template-columns: 2rem minmax(0, 1fr) auto auto; align-items: center; gap: .7rem; padding: .5rem .6rem; border-radius: var(--radius-s); cursor: pointer; position: relative; }
    li.sel { background: var(--hover); }
    li.sel::before { content: ''; position: absolute; left: 0; top: .45rem; bottom: .45rem; width: 3px; border-radius: 3px; background: var(--k); }
    .tile { display: grid; place-items: center; width: 2rem; height: 2rem; border-radius: 8px; font: 700 .85rem var(--mono); color: var(--k); background: color-mix(in srgb, var(--k) 13%, var(--raised)); }
    .txt { display: grid; min-width: 0; }
    .t, .s { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .t { font-weight: 600; }
    .s { color: var(--muted); font: 12.5px var(--mono); }
    mark { background: none; color: var(--brand); font-weight: 800; text-decoration: underline; text-decoration-thickness: 2px; text-underline-offset: 3px; }
    .kind { font: 600 11px var(--mono); letter-spacing: .05em; text-transform: uppercase; color: var(--muted); }
    .ret { visibility: hidden; }
    li.sel .ret { visibility: visible; }
    .empty { margin: 0; padding: 1.4rem 1rem; text-align: center; color: var(--muted); }
    .empty.err { color: var(--danger); }
    .empty button { margin-left: .5rem; }
    .pulse { display: inline-block; width: .55rem; height: .55rem; border-radius: 50%; background: var(--brand); margin-right: .55rem; }
    .sr { position: absolute; width: 1px; height: 1px; overflow: hidden; clip-path: inset(50%); margin: 0; }
    footer { display: flex; flex-wrap: wrap; gap: .4rem 1.1rem; padding: .5rem .85rem; border-top: 1px solid var(--line-soft); background: var(--surface); color: var(--muted); font-size: 12px; }
    footer kbd { margin-right: .25rem; }
    @media (max-width: 700px) { dialog.cp { top: 6vh; } .kind, footer { display: none; } li { grid-template-columns: 2rem minmax(0, 1fr) auto; } .bar input { font-size: 16px; } }
  `,
})
export class CommandPalette {
  palette = inject(PaletteService);
  private api = inject(Api);
  private ui = inject(Ui);
  private router = inject(Router);
  private dlg = viewChild.required<ElementRef<HTMLDialogElement>>('dlg');
  private inp = viewChild.required<ElementRef<HTMLInputElement>>('inp');
  readonly kinds = KIND;

  raw = signal('');       // what the input shows
  private deb = signal(''); // debounced copy that drives the search
  sel = signal(0);
  state = signal<'idle' | 'loading' | 'ready' | 'error'>('idle');
  private data = signal<PaletteItem[]>([]);
  private loadedAt = 0;
  private timer?: ReturnType<typeof setTimeout>;
  private recent = signal<PaletteItem[]>(this.readRecent());

  /** `>`, `@`, `/` pick what is searched; the rest is the query. */
  private parsed = computed(() => {
    const r = this.deb().trimStart(), c = r[0];
    const kinds: Kind[] | null = c === '>' ? ['action'] : c === '@' ? ['device', 'host'] : c === '/' ? ['page'] : null;
    const label = c === '>' ? 'Actions' : c === '@' ? 'Devices' : c === '/' ? 'Pages' : '';
    return { kinds, label, q: (kinds ? r.slice(1) : r).trim() };
  });
  mode = computed(() => this.parsed());
  query = computed(() => this.parsed().q);

  hits = computed<Hit[]>(() => {
    const { kinds, q } = this.parsed();
    const dom = q.toLowerCase().replace(/\.$/, '');
    const typed: PaletteItem[] = DOMAIN.test(dom) ? [
      { id: 'a:check:' + dom, kind: 'action', title: `Check ${dom}`, sub: 'Domain check', act: { nav: ['/audit'], q: { domain: dom } } },
      { id: 'a:block:' + dom, kind: 'action', title: `Block ${dom}`, sub: 'Add to your blocklist', act: { block: dom } },
      { id: 'a:allow:' + dom, kind: 'action', title: `Allow ${dom}`, sub: 'Add an exception to your blocklist', act: { allow: dom } },
      { id: 'a:logs:' + dom, kind: 'action', title: `Show queries for ${dom}`, sub: 'DNS log', act: { nav: ['/logs/dns'], q: { q: dom } } },
    ] : [];
    const cmds: PaletteItem[] = this.palette.commands().map(c => ({ id: 'c:' + c.id, kind: 'action', title: c.title, sub: c.sub, keywords: c.keywords, act: { fn: c.run } }));
    let pool: PaletteItem[] = [...PAGES.map(p => ({ id: 'p:' + p.nav[0], kind: 'page' as Kind, title: p.title, keywords: p.kw, act: { nav: p.nav } })), ...cmds, ...this.data()];
    if (kinds) pool = pool.filter(i => kinds.includes(i.kind));
    if (!q) {
      if (kinds) return [...typed, ...pool].slice(0, MAX_SHOWN).map(item => ({ item, idx: [], score: 0 }));
      const seen = new Set<string>();
      return [...this.recent(), ...pool.filter(i => i.kind === 'page' || i.kind === 'action')].filter(i => !seen.has(i.id) && !!seen.add(i.id))
        .slice(0, MAX_SHOWN).map(item => ({ item, idx: [], score: 0 }));
    }
    const out: Hit[] = typed.map((item, i) => ({ item, idx: [], score: 1e6 - i }));
    for (const item of pool) {
      const m = fuzzy(q, item.title);
      if (m) { out.push({ item, idx: m.idx, score: m.score + (item.kind === 'page' ? 8 : 0) }); continue; }
      const h = fuzzy(q, `${item.sub ?? ''} ${item.keywords ?? ''}`);
      if (h) out.push({ item, idx: [], score: h.score * .5 });
    }
    return out.sort((a, b) => b.score - a.score).slice(0, MAX_SHOWN);
  });

  constructor() {
    effect(() => {
      const el = this.dlg().nativeElement;
      if (this.palette.isOpen()) {
        if (!el.open) { el.showModal(); this.raw.set(''); this.deb.set(''); this.sel.set(0); this.recent.set(this.readRecent()); }
        this.inp().nativeElement.focus();
        this.load(false);
      } else if (el.open) el.close();
    });
    effect(() => { this.hits(); this.sel.set(0); });
  }

  typed(v: string) {
    this.raw.set(v);
    clearTimeout(this.timer);
    this.timer = setTimeout(() => this.deb.set(v), 70);
  }

  /** Lazy on first open; cached for TTL. A part that fails leaves the rest usable (state 'error' shows a retry). */
  async load(force: boolean) {
    if (this.state() === 'loading' || (!force && this.state() === 'ready' && Date.now() - this.loadedAt < TTL)) return;
    this.state.set('loading');
    const [zones, recs, hosts, leases, blocked] = await Promise.allSettled([
      this.api.invoke(zonesList), this.api.invoke(recordsList, {}), this.api.invoke(hostsList), this.api.invoke(dhcpLeasesList, {}), this.api.invoke(blockedSuggestionsList, {}),
    ]);
    const items: PaletteItem[] = [], zname = new Map<number, string>();
    if (zones.status === 'fulfilled') for (const z of zones.value) { zname.set(z.id, z.name); items.push({ id: 'z:' + z.id, kind: 'zone', title: z.name, sub: z.reverse ? 'Reverse zone' : 'Zone', act: { nav: ['/zones', z.id] } }); }
    if (recs.status === 'fulfilled') for (const r of recs.value) {
      const z = zname.get(r.zone) ?? '', n = r.name && r.name !== '@' ? `${r.name}.${z}` : z;
      items.push({ id: 'r:' + r.id, kind: 'record', title: n, sub: `${r.type} ${r.value}`, act: { nav: ['/zones', r.zone] } });
    }
    if (hosts.status === 'fulfilled') for (const h of hosts.value) items.push({ id: 'h:' + h.id, kind: 'host', title: h.name, sub: h.address, act: { nav: ['/zones/hosts'] } });
    if (leases.status === 'fulfilled') {
      const seen = new Set<string>();
      for (const l of leases.value) {
        const id = `d:${l.mac}:${l.address}`; if (seen.has(id)) continue; seen.add(id);
        items.push({ id, kind: 'device', title: l.hostname || l.client || l.address, sub: `${l.address} · ${l.mac}`, keywords: l.vendor, act: { nav: ['/dhcp/leases'] } });
      }
    }
    if (blocked.status === 'fulfilled') for (const b of blocked.value) items.push({ id: 'b:' + b.name, kind: 'blocked', title: b.name, sub: `blocked ${b.count}×`, act: { nav: ['/logs/dns'], q: { q: b.name } } });
    this.data.set(items);
    const failed = [zones, recs, hosts, leases, blocked].filter(r => r.status === 'rejected').length;
    this.loadedAt = Date.now();
    this.state.set(failed ? 'error' : 'ready');
  }

  parts(h: Hit) {
    const t = h.item.title, set = new Set(h.idx), out: { s: string; m: boolean }[] = [];
    for (let i = 0; i < t.length; i++) { const m = set.has(i), l = out[out.length - 1]; if (l && l.m === m) l.s += t[i]; else out.push({ s: t[i], m }); }
    return out;
  }

  keys(e: KeyboardEvent) {
    const n = this.hits().length;
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault(); if (!n) return;
      this.sel.set((this.sel() + (e.key === 'ArrowDown' ? 1 : n - 1)) % n);
      document.getElementById('cp-o' + this.sel())?.scrollIntoView({ block: 'nearest' });
    } else if (e.key === 'Enter') {
      e.preventDefault(); clearTimeout(this.timer); this.deb.set(this.raw()); // act on what is on screen
      const h = this.hits()[this.sel()]; if (h) this.run(h.item);
    } else if (e.key === 'Tab') e.preventDefault(); // focus stays in the combobox; arrows move
  }

  run(item: PaletteItem) {
    this.remember(item);
    this.palette.close();
    const a = item.act;
    if ('nav' in a) return void this.router.navigate(a.nav, a.q ? { queryParams: a.q } : {});
    if ('fn' in a) return void this.ui.run(async () => { await a.fn(); });
    return void this.setBlock('block' in a ? a.block : a.allow, 'allow' in a);
  }

  /** Same call and Undo as the Blocklist page (no step-up there; Ui.run shows any error, the interceptor handles 401). */
  private setBlock(name: string, allow: boolean) {
    return this.ui.run(async () => {
      const made = await this.api.invoke(blockedCreate, { body: { name, allow } });
      this.ui.toast(`${allow ? 'Allowed' : 'Blocked'} ${name}`, async () => { await this.api.invoke(blockedDestroy, { id: made.id }); });
    });
  }

  private readRecent(): PaletteItem[] {
    try { const r = JSON.parse(localStorage.getItem(RECENT_KEY) ?? '[]'); return Array.isArray(r) ? r.filter(i => i?.id && i.act && !('fn' in i.act)) : []; } catch { return []; }
  }
  private remember(i: PaletteItem) {
    if ('fn' in i.act) return; // functions cannot be stored
    const list = [i, ...this.recent().filter(r => r.id !== i.id)].slice(0, 6);
    this.recent.set(list);
    try { localStorage.setItem(RECENT_KEY, JSON.stringify(list)); } catch { /* private mode: recents are a nicety */ }
  }
}
