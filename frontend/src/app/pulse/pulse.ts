/**
 * NETWORK PULSE: live map of DNS traffic. Standalone, lazy. Nothing outside src/app/pulse/ was touched; add these two things yourself.
 *
 * 1) src/app/app.routes.ts, inside the Shell children (next to the 'geo' route):
 *    { path: 'pulse', title: 'Network pulse', loadComponent: () => import('./pulse/pulse').then(m => m.PulsePage) },
 *
 * 2) src/app/shell/shell.ts, in SECTIONS (next to '/geo'; 'map' is an existing icon name, any IconName works):
 *    { path: '/pulse', label: 'Network pulse', icon: 'map', primary: false },
 */
import { DecimalPipe } from '@angular/common';
import { Component, ElementRef, NgZone, OnDestroy, computed, inject, signal, viewChild } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Api } from '../api/api';
import { blockedCreate, logsClientsList, logsList } from '../api/functions';
import { QueryLog } from '../api/models';
import { byIp } from '../lib/ip';
import { Ui } from '../services/ui';

type Kind = 'local' | 'cache' | 'fwd' | 'error' | 'blocked';
interface Row { id: number; t: number; client: string; name: string; outcome: string; via: string; kind: Kind }
interface Dev { ip: string; label: string; x: number; y: number; rate: number; vis: number; count: number; blocked: number; doms: Map<string, number>; rows: Row[] }
interface Snap { ip: string; label: string; x: number; y: number; qps: number; count: number; blocked: number; top: [string, number][]; rows: Row[] }
interface Part { dev: Dev; kind: Kind; t: number; dur: number; bend: number; bucket: number }
interface Spark { x: number; y: number; vx: number; vy: number; life: number }

const KINDS: Kind[] = ['local', 'cache', 'fwd', 'error', 'blocked'];
const NAMES: Record<Kind, string> = { local: 'Internal', cache: 'Cache', fwd: 'Upstream', error: 'Error', blocked: 'Blocked' };
const VARS: Record<Kind, string> = { local: '--ok', cache: '--c-prx', fwd: '--brand', error: '--warn', blocked: '--danger' };
const BX = [0.14, 0.32, 0.5, 0.68, 0.86], BY = 0.93; // bucket slots along the bottom
const CX = 0.5, CY = 0.45, RX = 0.4, RY = 0.33; // core and device ellipse, as fractions of the stage
const POLL = 2000, MAX_DEV = 40, REPLAY_MS = 15 * 60e3, REPLAY_RATE = 30, HIST = 6000;
const CAP = [120, 220, 300]; // particle cap per quality level

const kindOf = (l: QueryLog): Kind => {
  if (l.outcome === 'blocked') return 'blocked';
  if (l.outcome === 'error') return 'error';
  if (/cache/i.test(l.via ?? '')) return 'cache';
  return l.outcome === 'local' ? 'local' : 'fwd';
};
const toRow = (l: QueryLog): Row => ({ id: l.id, t: Date.parse(l.time), client: l.client, name: l.name, outcome: l.outcome, via: l.via ?? '', kind: kindOf(l) });
const bez = (a: number, b: number, c: number, u: number) => (1 - u) * (1 - u) * a + 2 * (1 - u) * u * b + u * u * c;

@Component({
  selector: 'app-pulse-page',
  imports: [FormsModule, DecimalPipe],
  template: `
<header class="top">
  <div>
    <h2>Network pulse</h2>
    <p class="soft">Every DNS query as it happens: from the device, through the resolver, to where it was answered.</p>
  </div>
  <div class="ctl">
    <button class="ghost" type="button" (click)="togglePause()" [attr.aria-pressed]="paused()">{{ paused() ? 'Resume' : 'Pause' }}</button>
    <label>Speed
      <select [ngModel]="speed()" (ngModelChange)="speed.set(+$event)" name="sp">
        <option [ngValue]="0.5">0.5x</option><option [ngValue]="1">1x</option><option [ngValue]="2">2x</option><option [ngValue]="4">4x</option>
      </select></label>
    <label>Outcome
      <select [ngModel]="outcome()" (ngModelChange)="outcome.set($event)" name="oc">
        <option value="all">All</option>
        @for (k of kinds; track k) { <option [value]="k">{{ names[k] }}</option> }
      </select></label>
    <label class="chk"><input type="checkbox" [ngModel]="onlyBlocked()" (ngModelChange)="onlyBlocked.set($event)" name="ob"> Show only blocked</label>
    @if (!reduced()) {
      <button class="ghost" type="button" (click)="mode() === 'live' ? startReplay() : endReplay()">{{ mode() === 'live' ? 'Replay 15 min' : 'Back to live' }}</button>
    }
  </div>
</header>

<p class="sr-only" role="status" aria-live="polite">{{ summary() }}</p>

@if (mode() === 'replay') {
  <div class="scrub">
    <button class="ghost" type="button" (click)="playing.set(!playing())">{{ playing() ? 'Pause replay' : 'Play replay' }}</button>
    <input type="range" min="0" max="1000" [ngModel]="slider()" (ngModelChange)="seek(+$event)" name="sc" aria-label="Replay position">
    <span class="mono">{{ replayTime() }}</span>
  </div>
}

<div class="grid">
  @if (!reduced()) {
    <div class="stage" #stage aria-label="Devices around the resolver">
      <canvas #cv aria-hidden="true"></canvas>
      @for (d of devs(); track d.ip) {
        <button type="button" class="node" [style.left.%]="d.x * 100" [style.top.%]="d.y * 100"
          [attr.aria-pressed]="pinned() === d.ip" [attr.aria-label]="d.label + ', ' + (d.qps | number:'1.1-1') + ' queries per second, ' + d.count + ' total'"
          (mouseenter)="hover(d.ip)" (mouseleave)="hover('')" (focus)="hover(d.ip)" (blur)="hover('')" (click)="pin(d.ip)"></button>
      }
      @if (tip(); as t) {
        <div class="tip" [style.left.%]="t.x * 100" [style.top.%]="t.y * 100" [class.below]="t.y < 0.5" role="tooltip">
          <b>{{ t.label }}</b>
          <span>{{ t.qps | number:'1.1-1' }} queries/s, {{ t.count | number }} seen</span>
          @for (x of t.top; track x[0]) { <span class="mono">{{ x[0] }} <i>{{ x[1] }}</i></span> }
        </div>
      }
      @if (!devs().length) { <p class="empty soft">Waiting for the first queries.</p> }
    </div>
  } @else {
    <section class="calm" aria-label="Devices by activity">
      <p class="soft">Reduced motion is on: activity is shown as bars and a list instead of moving particles.</p>
      @for (d of byRate(); track d.ip) {
        <button type="button" class="bar" [class.on]="pinned() === d.ip" (click)="pin(d.ip)">
          <span class="who">{{ d.label }}</span>
          <span class="track"><span [style.width.%]="d.pct"></span></span>
          <span class="mono">{{ d.qps | number:'1.1-1' }}/s</span>
        </button>
      } @empty { <p class="soft">Waiting for the first queries.</p> }
    </section>
  }

  <aside class="side">
    <ul class="legend" aria-label="Where queries ended up">
      @for (k of kinds; track k) {
        <li><i class="sw" [attr.data-k]="k"></i>{{ names[k] }} <b class="mono">{{ totals()[k] | number }}</b></li>
      }
    </ul>
    @if (pinnedSnap(); as p) {
      <section aria-label="Latest queries">
        <div class="ph"><h3>{{ p.label }}</h3><button class="ghost mini" type="button" (click)="pin('')">Unpin</button></div>
        <p class="soft">{{ p.ip }} - {{ p.qps | number:'1.1-1' }} queries/s, {{ p.blocked | number }} blocked</p>
        <ul class="qs">
          @for (r of p.rows; track r.id) {
            <li>
              <span class="mono nm" [title]="r.name">{{ r.name }}</span>
              <span class="chip" [attr.data-k]="r.kind">{{ names[r.kind] }}</span>
              @if (r.kind === 'blocked') {
                @if (r.via !== 'rate limit') { <button class="ghost mini" type="button" (click)="allow(r.name)">Allow</button> }
              } @else { <button class="ghost mini" type="button" (click)="block(r.name)">Block</button> }
            </li>
          }
        </ul>
      </section>
    } @else if (reduced()) {
      <p class="soft">Pick a device to see its latest queries.</p>
    } @else {
      <p class="soft">Hover or focus a device for its busiest domains. Click to pin it and see its latest queries.</p>
    }
    @if (reduced()) {
      <section aria-label="Latest queries on the network">
        <h3>Latest queries</h3>
        <ul class="qs">
          @for (r of latest(); track r.id) {
            <li><span class="mono nm">{{ r.name }}</span><span class="chip" [attr.data-k]="r.kind">{{ names[r.kind] }}</span><span class="soft">{{ label(r.client) }}</span></li>
          }
        </ul>
      </section>
    }
  </aside>
</div>
`,
  styles: `
:host { display: block; --k-local: var(--ok); --k-cache: var(--c-prx); --k-fwd: var(--brand); --k-error: var(--warn); --k-blocked: var(--danger); }
.top { display: flex; flex-wrap: wrap; gap: 1rem; justify-content: space-between; align-items: flex-end; margin-bottom: 1rem; }
.ctl { display: flex; flex-wrap: wrap; gap: .6rem 1rem; align-items: center; }
.ctl label { display: inline-flex; gap: .4rem; align-items: center; font-size: 14px; color: var(--muted); }
.ctl select { padding: .4rem .6rem; }
.ctl .chk { color: var(--ink); } .ctl .chk input { width: 1.1rem; height: 1.1rem; padding: 0; }
.scrub { display: flex; gap: .8rem; align-items: center; margin-bottom: .8rem; } .scrub input { flex: 1; padding: 0; }
.grid { display: grid; grid-template-columns: minmax(0, 1fr) 20rem; gap: 1rem; align-items: start; }
@media (max-width: 960px) { .grid { grid-template-columns: 1fr; } }
.stage { position: relative; height: clamp(420px, 72vh, 780px); border-radius: var(--radius); overflow: hidden; box-shadow: var(--shadow);
  background: radial-gradient(circle at 50% 45%, color-mix(in srgb, var(--brand) 9%, var(--sunk)), var(--sunk) 70%); }
canvas { position: absolute; inset: 0; width: 100%; height: 100%; display: block; }
.node { position: absolute; width: 34px; height: 34px; margin: -17px 0 0 -17px; border-radius: 50%; border: 0; background: transparent; padding: 0; }
.node:hover, .node[aria-pressed=true] { box-shadow: 0 0 0 2px var(--brand); }
@media (pointer: coarse) { .node { width: 44px; height: 44px; margin: -22px 0 0 -22px; } }
.tip { position: absolute; transform: translate(-50%, calc(-100% - 22px)); display: grid; gap: .1rem; min-width: 12rem; max-width: 18rem; pointer-events: none;
  background: var(--raised); color: var(--ink); border-radius: var(--radius-s); padding: .5rem .7rem; font-size: 13px; box-shadow: var(--shadow-pop); z-index: 2; }
.tip.below { transform: translate(-50%, 22px); }
.tip i { font-style: normal; color: var(--muted); float: right; margin-left: .8rem; }
.empty { position: absolute; inset: auto 0 45% 0; text-align: center; }
.side { display: grid; gap: 1rem; }
.legend { list-style: none; margin: 0; padding: .7rem .9rem; display: grid; gap: .35rem; background: var(--surface); border-radius: var(--radius); box-shadow: var(--shadow); }
.legend li { display: flex; align-items: center; gap: .5rem; } .legend b { margin-left: auto; font-weight: 700; }
.sw { width: .9rem; height: .9rem; border-radius: 50%; background: var(--c); display: inline-block; }
[data-k=local] { --c: var(--k-local); } [data-k=cache] { --c: var(--k-cache); } [data-k=fwd] { --c: var(--k-fwd); } [data-k=error] { --c: var(--k-error); } [data-k=blocked] { --c: var(--k-blocked); }
.sw[data-k=cache] { background: transparent; border: 2px dotted var(--c); } .sw[data-k=fwd] { background: transparent; border: 2px solid var(--c); }
.side section { background: var(--surface); border-radius: var(--radius); box-shadow: var(--shadow); padding: .8rem .9rem; }
.ph { display: flex; justify-content: space-between; align-items: center; gap: .5rem; } h3 { margin: 0; font-size: 1rem; }
.qs { list-style: none; margin: .5rem 0 0; padding: 0; max-height: 26rem; overflow: auto; display: grid; gap: .1rem; }
.qs li { display: flex; align-items: center; gap: .5rem; padding: .25rem 0; border-top: 1px solid var(--line-soft); }
.nm { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.chip { font-size: 12px; padding: .05rem .5rem; border-radius: 999px; border: 1px solid var(--c); color: var(--ink); }
button.mini { min-height: 30px; padding: .2rem .6rem; font-size: 13px; }
.calm { display: grid; gap: .4rem; }
.bar { display: grid; grid-template-columns: 11rem 1fr 4.5rem; gap: .7rem; align-items: center; text-align: left; background: var(--surface); border: 1px solid var(--line-soft); border-radius: var(--radius-s); padding: .45rem .7rem; }
.bar.on { border-color: var(--brand); } .who { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.track { height: .7rem; background: var(--sunk); border-radius: 99px; overflow: hidden; } .track span { display: block; height: 100%; background: var(--brand); border-radius: 99px; }
`,
})
export class PulsePage implements OnDestroy {
  private api = inject(Api);
  private zone = inject(NgZone);
  private host = inject<ElementRef<HTMLElement>>(ElementRef);
  ui = inject(Ui);
  kinds = KINDS; names = NAMES;
  private cv = viewChild<ElementRef<HTMLCanvasElement>>('cv');
  private stage = viewChild<ElementRef<HTMLElement>>('stage');

  paused = signal(false); speed = signal(1); outcome = signal('all'); onlyBlocked = signal(false);
  mode = signal<'live' | 'replay'>('live'); playing = signal(true); slider = signal(1000);
  reduced = signal(matchMedia('(prefers-reduced-motion: reduce)').matches);
  devs = signal<Snap[]>([]); pinned = signal(''); hot = signal('');
  totals = signal<Record<Kind, number>>({ local: 0, cache: 0, fwd: 0, error: 0, blocked: 0 });
  summary = signal(''); latest = signal<Row[]>([]); replayTime = signal('');
  private names2 = new Map<string, string>();

  tip = computed(() => this.devs().find(d => d.ip === this.hot()));
  pinnedSnap = computed(() => this.devs().find(d => d.ip === this.pinned()));
  byRate = computed(() => { const l = [...this.devs()].sort((a, b) => b.qps - a.qps), m = Math.max(0.01, l[0]?.qps ?? 0); return l.map(d => ({ ...d, pct: (d.qps / m) * 100 })); });

  private devMap = new Map<string, Dev>();
  private parts: Part[] = []; private sparks: Spark[] = [];
  private queue: { at: number; row: Row }[] = [];
  private hist: Row[] = []; private cursor = 0; private pos = 0;
  private lastId = 0; private inflight = false; private destroyed = false;
  private poll?: ReturnType<typeof setTimeout>; private tickTimer?: ReturnType<typeof setInterval>; private raf = 0;
  private quality = 2; private ft = 16; private last = 0; private ro?: ResizeObserver; private w = 1; private h = 1; private dpr = 1;
  private burstAt: number[] = []; private win: Row[] = []; private colors: Record<string, string> = {};
  private others = 0; private t0 = performance.now();

  private mq = matchMedia('(prefers-reduced-motion: reduce)');
  private onMq = () => { this.reduced.set(this.mq.matches); this.parts = []; this.sparks = []; this.queue = []; this.loop(); };
  private onVis = () => { if (document.hidden) { clearTimeout(this.poll); this.stopLoop(); } else { this.schedule(0); this.loop(); } };

  constructor() {
    this.mq.addEventListener('change', this.onMq);
    document.addEventListener('visibilitychange', this.onVis);
    this.tickTimer = setInterval(() => this.tick(), 1000);
    this.loadNames();
    this.fetch(true).then(() => this.schedule(POLL));
    queueMicrotask(() => setTimeout(() => this.setup()));
  }

  ngOnDestroy() {
    this.destroyed = true; clearTimeout(this.poll); clearInterval(this.tickTimer); this.stopLoop(); this.ro?.disconnect();
    this.mq.removeEventListener('change', this.onMq); document.removeEventListener('visibilitychange', this.onVis);
  }

  // ---- data ----
  label(ip: string) { return this.names2.get(ip) || ip; }
  private async loadNames() {
    try { const r = await this.api.invoke(logsClientsList, { hours: 1 }); for (const c of r) if (c.host) this.names2.set(c.ip, c.host); } catch { /* names are a nicety */ }
  }
  private schedule(ms: number) {
    clearTimeout(this.poll);
    this.poll = setTimeout(async () => {
      if (this.destroyed || document.hidden || this.paused()) return; // resume/visibility restarts the loop
      await this.fetch(false);
      if (!this.destroyed && !this.paused() && !document.hidden) this.schedule(POLL);
    }, ms);
  }
  /** One request at a time; only rows newer than the last id are used. */
  private async fetch(first: boolean) {
    if (this.inflight) return;
    this.inflight = true;
    try {
      await this.ui.run(async () => {
        const r = await this.api.invoke(logsList, first ? { hours: 1, limit: 500 } : { limit: 200 });
        const rows = r.results.map(toRow).filter(x => x.id > this.lastId).sort((a, b) => a.id - b.id);
        if (rows.length) this.ingest(rows, first);
      }, { silent: true });
    } finally { this.inflight = false; }
  }
  private ingest(rows: Row[], first: boolean) {
    this.lastId = rows[rows.length - 1].id;
    this.hist.push(...rows); if (this.hist.length > HIST) this.hist.splice(0, this.hist.length - HIST);
    if (first) { for (const r of rows) this.dev(r.client); this.relayout(); return; }
    if (this.mode() === 'replay') return;
    const now = performance.now(), span = Math.max(1, rows[rows.length - 1].t - rows[0].t), fit = Math.min(POLL * 0.9, span);
    for (const r of rows) {
      if (this.reduced() || !this.cv()) this.emit(r);
      else this.queue.push({ at: now + ((r.t - rows[0].t) / span) * fit, row: r }); // spread over the poll window: no bursts, no clock-skew trouble
    }
    if (this.queue.length > 600) this.queue.splice(0, this.queue.length - 600);
    this.loop();
  }

  private dev(ip: string): Dev | undefined {
    let d = this.devMap.get(ip);
    if (!d) {
      if (this.devMap.size >= MAX_DEV) { this.others++; return; } // shortcut: devices past 40 are not drawn, raise MAX_DEV if needed
      d = { ip, label: ip, x: CX, y: CY, rate: 0, vis: 0, count: 0, blocked: 0, doms: new Map(), rows: [] };
      this.devMap.set(ip, d);
    }
    return d;
  }
  private relayout() {
    const l = [...this.devMap.values()].sort((a, b) => byIp(a.ip, b.ip));
    l.forEach((d, i) => { const a = -Math.PI / 2 + (2 * Math.PI * i) / l.length; d.x = CX + RX * Math.cos(a); d.y = CY + RY * Math.sin(a); });
    this.snap();
  }
  private snap() {
    const bump = this.devs().length !== this.devMap.size;
    if (bump) { this.devMap.forEach(d => d.label = this.label(d.ip)); }
    this.devMap.forEach(d => d.label = this.label(d.ip));
    this.devs.set([...this.devMap.values()].sort((a, b) => byIp(a.ip, b.ip)).map(d => ({
      ip: d.ip, label: d.label, x: d.x, y: d.y, qps: d.rate * 0.18, count: d.count, blocked: d.blocked,
      top: [...d.doms].sort((a, b) => b[1] - a[1]).slice(0, 3), rows: d.rows,
    })));
  }

  private pass(r: Row) { return this.onlyBlocked() ? r.kind === 'blocked' : this.outcome() === 'all' || this.outcome() === r.kind; }

  /** A row reaches the resolver now: stats always, a particle if it passes the filter and motion is on. */
  private emit(r: Row) {
    const had = this.devMap.has(r.client), d = this.dev(r.client);
    if (!d) return;
    if (!had) this.relayout();
    d.count++; d.rate += this.mode() === 'replay' ? 1 / (REPLAY_RATE * this.speed()) : 1;
    if (r.kind === 'blocked') d.blocked++;
    d.doms.set(r.name, (d.doms.get(r.name) ?? 0) + 1); if (d.doms.size > 200) d.doms.clear(); // shortcut: crude trim, top domains restart
    d.rows.unshift(r); if (d.rows.length > 40) d.rows.pop();
    this.win.push(r);
    const lt = this.latest(); this.latest.set([r, ...lt].slice(0, 30));
    if (this.reduced() || !this.pass(r) || this.parts.length >= CAP[this.quality]) { if (this.reduced()) this.arrive(r.kind); return; }
    this.parts.push({ dev: d, kind: r.kind, t: 0, dur: 1.7, bend: (Math.random() - 0.5) * 0.18, bucket: BX[KINDS.indexOf(r.kind)] });
  }
  private arrive(k: Kind) { const t = this.totals(); this.totals.set({ ...t, [k]: t[k] + 1 }); }

  private tick() {
    this.devMap.forEach(d => (d.rate *= 0.82));
    this.snap();
    const secs = Math.max(1, Math.min(10, (performance.now() - this.t0) / 1000)), w = this.win; this.win = [];
    if (Math.round((performance.now() - this.t0) / 1000) % 10 === 0) {
      const b = w.filter(x => x.kind === 'blocked').length;
      this.summary.set(`Last seconds: ${w.length} queries from ${new Set(w.map(x => x.client)).size} devices, ${b} blocked.`);
    }
    void secs;
    const cs = getComputedStyle(this.host.nativeElement);
    for (const v of ['--ok', '--c-prx', '--brand', '--warn', '--danger', '--ink', '--muted', '--line-soft', '--line']) this.colors[v] = cs.getPropertyValue(v).trim();
  }

  // ---- controls ----
  togglePause() {
    this.paused.update(p => !p);
    if (this.paused()) { clearTimeout(this.poll); this.stopLoop(); } else { this.schedule(0); this.loop(); }
  }
  hover(ip: string) { this.hot.set(ip); }
  pin(ip: string) { this.pinned.set(this.pinned() === ip ? '' : ip); }
  startReplay() {
    const to = this.hist.at(-1)?.t ?? 0, from = Math.max(this.hist[0]?.t ?? to, to - REPLAY_MS);
    this.mode.set('replay'); this.parts = []; this.queue = []; this.seek(0, from);
  }
  endReplay() { this.mode.set('live'); this.parts = []; this.sparks = []; }
  private range() { const to = this.hist.at(-1)?.t ?? 0; return [Math.max(this.hist[0]?.t ?? to, to - REPLAY_MS), to]; }
  seek(v: number, from?: number) {
    const [a, b] = this.range(); this.slider.set(v);
    this.pos = (from ?? a) + ((b - (from ?? a)) * v) / 1000;
    this.cursor = Math.max(0, this.hist.findIndex(r => r.t > this.pos)); if (this.cursor === 0 && this.hist.at(-1)!.t <= this.pos) this.cursor = this.hist.length;
    this.parts = []; this.replayTime.set(new Date(this.pos).toLocaleTimeString());
  }

  block(name: string) {
    this.ui.ask(`Block ${name}?`, 'The domain and its subdomains will receive NXDOMAIN from the next query. Undo it in Blocklist > Personal blocks.', () =>
      this.ui.run(async () => { await this.api.invoke(blockedCreate, { body: { name } }); }, { ok: `Blocked ${name}` }), 'Block domain');
  }
  allow(name: string) {
    this.ui.ask(`Allow ${name}?`, 'The name and its subdomains will never be blocked by the public lists. Remove the exception in Blocklist > Personal blocks.', () =>
      this.ui.run(async () => { await this.api.invoke(blockedCreate, { body: { name, allow: true } }); }, { ok: `Allowed ${name}` }), 'Allow name');
  }

  // ---- canvas ----
  private setup() {
    const st = this.stage()?.nativeElement, cv = this.cv()?.nativeElement;
    if (!st || !cv || this.ro) { if (!this.ro && !this.destroyed) setTimeout(() => this.setup(), 200); return; }
    const size = () => { this.dpr = this.quality ? Math.min(2, devicePixelRatio || 1) : 1; this.w = st.clientWidth; this.h = st.clientHeight; cv.width = this.w * this.dpr; cv.height = this.h * this.dpr; };
    this.ro = new ResizeObserver(size); this.ro.observe(st); size(); this.tick(); this.loop();
  }
  private loop() {
    if (this.raf || this.destroyed || this.paused() || document.hidden || this.reduced() || !this.cv()) return;
    this.last = performance.now();
    this.zone.runOutsideAngular(() => { const f = (t: number) => { this.frame(t); this.raf = this.destroyed || this.paused() || document.hidden || this.reduced() ? 0 : requestAnimationFrame(f); }; this.raf = requestAnimationFrame(f); });
  }
  private stopLoop() { cancelAnimationFrame(this.raf); this.raf = 0; }

  private frame(now: number) {
    const dt = Math.min(0.05, (now - this.last) / 1000); this.last = now;
    this.ft = this.ft * 0.95 + dt * 1000 * 0.05;
    if (this.ft > 26 && this.quality > 0) { this.quality--; this.ft = 16; } else if (this.ft < 12 && this.quality < 2) { this.quality++; this.ft = 16; } // adapt to frame time
    const sp = this.speed();
    if (this.mode() === 'live') {
      while (this.queue.length && this.queue[0].at <= now) { const q = this.queue.shift()!; this.emit(q.row); }
    } else if (this.playing()) {
      this.pos += dt * 1000 * REPLAY_RATE * sp;
      while (this.cursor < this.hist.length && this.hist[this.cursor].t <= this.pos) this.emit(this.hist[this.cursor++]);
      const [a, b] = this.range(); this.slider.set(Math.min(1000, Math.round(((this.pos - a) / Math.max(1, b - a)) * 1000)));
      this.replayTime.set(new Date(this.pos).toLocaleTimeString());
      if (this.cursor >= this.hist.length) this.playing.set(false);
    }
    for (const p of this.parts) {
      p.t += (dt * sp) / p.dur;
      if (p.kind === 'blocked' && p.t >= 0.5) { p.t = 2; this.arrive('blocked'); this.burst(p); } else if (p.t >= 1) this.arrive(p.kind);
    }
    this.parts = this.parts.filter(p => p.t < 1);
    for (const s of this.sparks) { s.x += s.vx * dt; s.y += s.vy * dt; s.life -= dt * 1.4; }
    this.sparks = this.sparks.filter(s => s.life > 0);
    this.draw(now / 1000);
  }
  private burst(p: Part) {
    const n = performance.now(); this.burstAt = this.burstAt.filter(t => n - t < 1000);
    if (this.burstAt.length >= 2 || !this.quality) return; // never more than 2 bursts a second
    this.burstAt.push(n);
    for (let i = 0; i < 7 + this.quality * 3; i++) { const a = Math.random() * 6.28, v = 20 + Math.random() * 50; this.sparks.push({ x: CX * this.w, y: CY * this.h, vx: Math.cos(a) * v, vy: Math.sin(a) * v, life: 1 }); }
    void p;
  }
  private col(k: Kind) { return this.colors[VARS[k]] || '#888'; }

  private draw(sec: number) {
    const cv = this.cv()?.nativeElement, g = cv?.getContext('2d'); if (!cv || !g) return;
    const { w, h } = this, cx = CX * w, cy = CY * h, ink = this.colors['--ink'] || '#888', muted = this.colors['--muted'] || '#888', line = this.colors['--line'] || '#888';
    g.setTransform(this.dpr, 0, 0, this.dpr, 0, 0); g.clearRect(0, 0, w, h);
    // rings and a slow sweep around the resolver
    g.strokeStyle = line; g.lineWidth = 1;
    for (let i = 1; i <= 3; i++) { g.globalAlpha = 0.16; g.beginPath(); g.ellipse(cx, cy, RX * w * (i / 3) * 0.95, RY * h * (i / 3) * 0.95, 0, 0, 6.283); g.stroke(); }
    const a = (sec * 0.5) % 6.283; g.globalAlpha = 0.5; g.strokeStyle = this.colors['--brand'] || '#47f';
    g.beginPath(); g.moveTo(cx, cy); g.lineTo(cx + Math.cos(a) * RX * w, cy + Math.sin(a) * RY * h); g.stroke();
    const pin = this.pinned();
    // links
    for (const d of this.devMap.values()) {
      g.globalAlpha = (pin && pin !== d.ip ? 0.05 : 0.1) + Math.min(0.3, d.rate * 0.03); g.strokeStyle = line;
      g.beginPath(); g.moveTo(d.x * w, d.y * h); g.lineTo(cx, cy); g.stroke();
    }
    // buckets
    g.font = '12px ' + getComputedStyle(this.host.nativeElement).fontFamily; g.textAlign = 'center';
    const tot = this.totals();
    KINDS.forEach((k, i) => {
      const x = BX[i] * w, y = BY * h; g.globalAlpha = 0.9; g.strokeStyle = this.col(k); g.lineWidth = 2;
      g.setLineDash(k === 'cache' ? [2, 4] : []); g.beginPath(); g.arc(x, y - 14, 9, 0, 6.283); g.stroke(); g.setLineDash([]);
      g.fillStyle = ink; g.fillText(`${NAMES[k]} ${tot[k]}`, x, y + 12);
    });
    // particles: trail style tells the path (solid local, long hollow upstream, dotted cache)
    const steps = [0, 3, 6][this.quality];
    for (const p of this.parts) {
      const c = this.col(p.kind), fade = p.kind === 'blocked' ? 1 : 1;
      for (let s = steps; s >= 0; s--) {
        const t = p.t - s * 0.025 * (p.kind === 'fwd' ? 1.6 : 1); if (t < 0) continue;
        if (p.kind === 'cache' && s % 2) continue;
        const [x, y] = this.at(p, t);
        g.globalAlpha = fade * (1 - s / (steps + 1)) * 0.9; g.fillStyle = c; g.strokeStyle = c;
        g.beginPath(); g.arc(x, y, s ? 2.2 - s * 0.2 : 3.2, 0, 6.283);
        if (!s && p.kind === 'fwd') { g.lineWidth = 1.5; g.stroke(); } else g.fill();
      }
    }
    // red sparks dissolving at the resolver
    g.fillStyle = this.col('blocked');
    for (const s of this.sparks) { g.globalAlpha = Math.max(0, s.life) * 0.8; g.beginPath(); g.arc(s.x, s.y, 2, 0, 6.283); g.fill(); }
    // devices: size and halo follow recent rate
    g.textAlign = 'center';
    const maxr = Math.max(0.5, ...[...this.devMap.values()].map(d => d.rate));
    const few = this.devMap.size <= 18;
    for (const d of this.devMap.values()) {
      d.vis += (Math.min(1, d.rate / maxr) * Math.min(1, 0.3 + d.rate * 0.2) - d.vis) * 0.08;
      const r = 6 + d.vis * 9, x = d.x * w, y = d.y * h, dim = pin && pin !== d.ip;
      if (this.quality) { g.globalAlpha = (dim ? 0.05 : 0.18) * (0.4 + d.vis); g.fillStyle = this.colors['--brand'] || '#47f'; g.beginPath(); g.arc(x, y, r * 2, 0, 6.283); g.fill(); }
      g.globalAlpha = dim ? 0.45 : 1; g.fillStyle = this.colors['--brand'] || '#47f'; g.beginPath(); g.arc(x, y, r, 0, 6.283); g.fill();
      if (d.ip === pin || d.ip === this.hot()) { g.strokeStyle = ink; g.lineWidth = 2; g.beginPath(); g.arc(x, y, r + 4, 0, 6.283); g.stroke(); }
      if (few || d.ip === pin || d.ip === this.hot() || d.vis > 0.4) { g.globalAlpha = dim ? 0.4 : 0.85; g.fillStyle = muted; g.fillText(this.label(d.ip), x, y + r + 14); }
    }
    // the resolver
    const pulse = 1 + Math.sin(sec * 1.2) * 0.04; g.globalAlpha = 1;
    g.fillStyle = this.colors['--ink'] || '#222'; g.beginPath(); g.arc(cx, cy, 24 * pulse, 0, 6.283); g.fill();
    g.fillStyle = this.colors['--brand'] || '#47f'; g.beginPath(); g.arc(cx, cy, 10, 0, 6.283); g.fill();
    g.fillStyle = ink; g.fillText('resolver', cx, cy + 44);
    g.globalAlpha = 1;
  }
  private at(p: Part, t: number): [number, number] {
    const { w, h } = this, ease = (u: number) => u * u * (3 - 2 * u), cx = CX * w, cy = CY * h;
    if (t < 0.5) {
      const u = ease(t * 2), ax = p.dev.x * w, ay = p.dev.y * h;
      return [bez(ax, (ax + cx) / 2 + (cy - ay) * p.bend, cx, u), bez(ay, (ay + cy) / 2 - (cx - ax) * p.bend, cy, u)];
    }
    const u = ease((t - 0.5) * 2), bx = p.bucket * w, by = BY * h - 14;
    return [bez(cx, (cx + bx) / 2 + (by - cy) * p.bend, bx, u), bez(cy, (cy + by) / 2, by, u)];
  }
}
