import { Component, ElementRef, OnDestroy, computed, effect, inject, untracked, input, signal, viewChild } from '@angular/core';
import qrcode from 'qrcode-generator';
import { DecimalPipe, NgTemplateOutlet } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, Router, RouterLink, RouterLinkActive } from '@angular/router';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { Api } from '../api/api';
import {
  proxyAllowCreate,
  proxyAllowUndoCreate,
  proxyInfoCreate,
  proxyInfoRetrieve,
  proxyRulesCreate,
  proxyRulesList,
  proxyLogsPurgeCreate,
  logsClientsList,
  proxyLogsGroupedRetrieve,
  proxyLogsRetrieve,
  proxyTestCreate,
  proxySettingsPartialUpdate,
  proxySettingsRetrieve,
  statusRetrieve,
} from '../api/functions';
import { ProxyAllow, ProxyLogGroup, ProxyRuleList, QueryLogClient, ProxySettings, ProxyInfo, ProxyLog, ProxyLogsResponse, ProxyTestResult, Status } from '../api/models';
import { Autocomplete } from '../lib/autocomplete';
import { InView } from '../lib/in-view';
import { byIp } from '../lib/ip';
import { DaemonStatusLine } from '../daemon-status/daemon-status';
import { blockLayer } from '../lib/proxy-reason';
import { fieldErrors } from '../lib/error-text';
import { SettingField, SettingsFields, changed } from '../dhcp-page/settings-fields';
import { StepUp } from '../services/step-up';
import { Period } from '../services/period';
import { Ui, saveFile } from '../services/ui';

const SERVER: SettingField[] = [
  { key: 'PROXY', kind: 'check', label: 'Run the ad-blocking proxy', help: 'Changes apply within 2 seconds while manage.py runproxy is running.' },
  { key: 'DHCP_WPAD', kind: 'check', label: 'Set up devices automatically', term: 'WPAD', help: 'Devices that look for a proxy find this one through DHCP and DNS. iPhone and Mac: use the profile below.' },
  { key: 'PROXY_PORT', kind: 'number', min: 1, max: 65535, label: 'Port', ph: '8080', help: 'TCP port the proxy listens on. Default 8080.' },
  { key: 'PROXY_ADDRESS', label: 'Listen on address', ph: 'empty: all interfaces', help: 'Empty: every interface, for the clients allowed in DNS_ALLOW_QUERY.' },
  { key: 'DHCP_WPAD_URL', label: 'Own setup file address', term: 'PAC URL', wide: true, ph: 'empty: http://<server IP>:<port>/wpad.dat', help: 'Only if you host your own wpad.dat. Empty: the built-in one.' },
];
const BLOCKING: SettingField[] = [
  { key: 'PROXY_BLOCK_ADS', kind: 'check', label: 'Block ads, banners and trackers', help: 'Blocks the Blocklist domains and ad addresses, and hides ad slots in pages.' },
  { key: 'PROXY_BLOCK_POPUPS', kind: 'check', label: 'Block popups', help: 'Stops pages from opening windows by themselves and from invisible click-catching layers.' },
  { key: 'PROXY_HTTPS_MITM', kind: 'check', label: 'Inspect HTTPS pages', term: 'HTTPS inspection', help: 'Off: secure sites are blocked or let through whole. On: their pages are filtered too; each device must trust the Root CA.' },
];
const SUGGESTED = [
  { name: 'easylist', label: 'EasyList', what: 'Ads and banners on web pages.', url: 'https://easylist.to/easylist/easylist.txt' },
  { name: 'easyprivacy', label: 'EasyPrivacy', what: 'Trackers and other privacy intrusions.', url: 'https://easylist.to/easylist/easyprivacy.txt' },
  { name: 'ublock-filters', label: 'uBlock filters', what: 'More ads and annoyances, kept up to date by the uBlock Origin project.', url: 'https://ublockorigin.github.io/uAssets/filters/filters.min.txt' },
];

@Component({
  selector: 'app-proxy-page',
  imports: [FormsModule, NgTemplateOutlet, DecimalPipe, RouterLink, RouterLinkActive, SettingsFields, DaemonStatusLine, Autocomplete, InView],
  templateUrl: './proxy-page.html',
})
export class ProxyPage implements OnDestroy {
  private api = inject(Api);
  ui = inject(Ui);
  private stepUp = inject(StepUp);
  private pg = viewChild<ElementRef<HTMLDialogElement>>('pg');
  purgeHours = 24;
  purgeCount = signal<number | null>(null);
  mode = input<'settings' | 'logs'>('settings', { alias: 'tab' }); // the :tab of the route /proxy/:tab
  cfg = signal<ProxySettings>({});
  private savedCfg: ProxySettings = {};
  errs = signal<Record<string, string>>({});
  info = signal<ProxyInfo | null>(null);
  loaded = signal(false);
  logsLoaded = signal(false);
  syncing = signal(false);
  readonly server = SERVER;
  readonly blocking = BLOCKING;
  readonly suggested = SUGGESTED;
  // the ad-block lists: kept as name=https://… words in PROXY_RULE_LISTS (what the server reads), shown as switches and a list
  private listEntries() {
    return (this.cfg().PROXY_RULE_LISTS || '').split(/[\s,]+/).filter(Boolean).map(w => {
      const [n, ...u] = w.split('=');
      return u.length ? { name: n, url: u.join('=') } : { name: w.split('?')[0].replace(/\/$/, '').split('/').pop()!.toLowerCase().replace(/[^a-z0-9._-]/g, '-').slice(0, 40) || 'list', url: w };
    });
  }
  private writeLists(e: { name: string; url: string }[]) { this.cfg.update(c => ({ ...c, PROXY_RULE_LISTS: e.map(x => `${x.name}=${x.url}`).join('\n') })); }
  customLists = computed(() => { this.cfg(); return this.listEntries().filter(e => !SUGGESTED.some(s => s.url === e.url)); });
  listOn(url: string) { return this.listEntries().some(e => e.url === url); }
  toggleList(s: { name: string; url: string }) {
    const e = this.listEntries();
    this.writeLists(this.listOn(s.url) ? e.filter(x => x.url !== s.url) : [...e.filter(x => x.name !== s.name), { name: s.name, url: s.url }]);
  }
  removeList(url: string) { this.writeLists(this.listEntries().filter(e => e.url !== url)); }
  listStat(name: string) { return this.rules().find(r => r.name === name); }
  rules = signal<ProxyRuleList[]>([]);
  testUrl = '';
  testResult = signal<ProxyTestResult | null>(null);
  status = signal<Status | null>(null); // is runproxy running (its heartbeat)
  allowedNow = signal<ReadonlySet<string>>(new Set()); // hosts allowed in DNS from this log (an @@ rule shows in the settings)
  copied = signal('');
  readonly blockLayer = blockLayer;
  /** Where devices download the setup files: https only (plain http is sent to GUI_URL), so this page's address when it is https, else GUI_URL. */
  setupBase = computed(() => location.protocol === 'https:' ? location.origin : (this.info()?.gui_url || location.origin));
  setup = computed(() => ['/proxy.mobileconfig', '/proxy-ca.crt'].map(path => {
    const url = this.setupBase() + path, q = qrcode(0, 'M');
    q.addData(url); q.make();
    return { url, qr: q.createDataURL(4, 8) };
  }));

  logsData = signal<ProxyLogsResponse>({
    count: 0,
    blocked_count: 0,
    filtered_count: 0,
    clients: [],
    results: [],
  });
  logQ = '';
  logOutcome: '' | 'allowed' | 'filtered' | 'blocked' | 'error' | 'timeout' = '';
  logClient = '';
  logMethod = '';
  logStatus = '';
  grouped = false; // one row per site, a click opens its requests (the DNS log's "Group by domain")
  ordering: 'last' | 'count' = 'last';
  groups = signal<ProxyLogGroup[]>([]);
  gCount = signal(0);
  openHosts = signal<{ [host: string]: { rows: ProxyLog[]; count: number } }>({});
  logDetail = '';
  logHours = 24;
  // the client filter works as the DNS log's: a list of the devices (names from the default zone) and an IP or name typed
  logClients = signal<QueryLogClient[]>([]);
  clientOptions = computed(() => this.logClients().map(c => ({ value: c.ip, label: c.host })).sort((a, b) => byIp(a.value, b.value)));
  private clientIp() { const c = this.logClient.trim().toLowerCase(); return c && this.logClients().find(x => x.host === c || x.name === c)?.ip || this.logClient.trim(); }
  async loadClients() {
    try { this.logClients.set(await this.api.invoke(logsClientsList, { hours: this.logHours || undefined })); } catch { /* the filter still works with a typed address */ }
  }
  live = true;
  private pollTimer?: ReturnType<typeof setInterval>;
  private searchTimer?: ReturnType<typeof setTimeout>;

  // Your own rules: kept as one line each in PROXY_CUSTOM_RULES (what the proxy reads), shown and edited as a list
  customRules = computed(() => (this.cfg().PROXY_CUSTOM_RULES || '').split(/\r?\n/).map(l => l.trim()).filter(Boolean).map(line => {
    if (line.startsWith('@@')) return { line, kind: 'Never filter', what: line.slice(2), where: '' };
    const i = line.indexOf('##');
    if (i >= 0) return { line, kind: 'Hide', what: line.slice(i + 2), where: line.slice(0, i) || 'every site' };
    return { line, kind: 'Block', what: line, where: '' };
  }));
  newKind: 'hide' | 'block' | 'allow' = 'hide';
  newSite = '';
  newValue = '';
  addRule() {
    const v = this.newValue.trim().replace(/^(@@|##)/, '');
    if (!v) return;
    const line = this.newKind === 'allow' ? '@@' + v : this.newKind === 'block' ? v : this.newSite.trim() + '##' + v;
    const old = this.cfg().PROXY_CUSTOM_RULES || '';
    if (!old.split(/\r?\n/).some(l => l.trim() === line)) this.cfg.update(c => ({ ...c, PROXY_CUSTOM_RULES: old.trim() ? old.replace(/\s+$/, '') + '\n' + line : line }));
    this.newValue = '';
  }
  removeRule(line: string) {
    this.cfg.update(c => ({ ...c, PROXY_CUSTOM_RULES: (c.PROXY_CUSTOM_RULES || '').split(/\r?\n/).filter(l => l.trim() !== line).join('\n') }));
  }

  allowedDomains = computed(() => {
    const raw = this.cfg().PROXY_CUSTOM_RULES || '';
    const set = new Set<string>();
    for (const line of raw.split(/\r?\n/)) {
      const s = line.trim();
      if (s.startsWith('@@') && s.length > 2) {
        set.add(s.slice(2).trim().toLowerCase());
      }
    }
    return set;
  });

  private route = inject(ActivatedRoute);
  private router = inject(Router);
  private periodStore = inject(Period);

  constructor() {
    this.load();
    this.loadClients();
    // the log filters live in the address (?outcome=&q=&client=&hours=): links from Statistics land filtered, Back and reload keep them
    this.route.queryParamMap.pipe(takeUntilDestroyed()).subscribe(p => {
      const o = p.get('outcome') ?? '', hp = p.get('hours'), h = hp === '0' ? 720 : Number(hp); // 0 (all) is the longest window here
      this.logOutcome = (['allowed', 'filtered', 'blocked', 'error', 'timeout'].includes(o) ? o : '') as typeof this.logOutcome;
      this.logQ = p.get('q') ?? '';
      this.logDetail = p.get('detail') ?? '';
      this.logMethod = p.get('method') ?? '';
      this.logStatus = /^([1-5]\d\d|[1-5]xx)$/.test(p.get('status') ?? '') ? p.get('status')! : '';
      this.logClient = p.get('client') ?? '';
      this.grouped = p.get('group') === '1';
      this.ordering = p.get('order') === 'count' ? 'count' : 'last';
      this.logHours = hp !== null && [1, 24, 168, 720].includes(h) ? h : this.periodStore.pick([1, 24, 168, 720]);
      if (this.mode() === 'logs') this.loadLogs();
    });
    effect(() => {
      const logs = this.mode() === 'logs';
      untracked(() => { // only the tab is tracked: loading logs flips signals that must not re-run this
        if (logs) { this.loadLogs(); this.syncPoll(); } else this.stopPoll();
      });
    });
  }

  ngOnDestroy() {
    this.stopPoll();
    if (this.searchTimer) clearTimeout(this.searchTimer);
  }

  load() {
    return this.ui.run(async () => {
      const [cfg, info, rules, status] = await Promise.all([
        this.api.invoke(proxySettingsRetrieve),
        this.api.invoke(proxyInfoRetrieve),
        this.api.invoke(proxyRulesList),
        this.api.invoke(statusRetrieve).catch(() => null), // unreadable: the line says “checking”
      ]);
      this.status.set(status);
      this.cfg.set(cfg);
      this.savedCfg = structuredClone(cfg);
      this.info.set(info);
      this.rules.set(rules);
      this.loaded.set(true);
    });
  }

  private logSeq = 0;
  private logParams() {
    return {
      q: this.logQ.trim() || undefined,
      detail: this.logDetail.trim() || undefined,
      outcome: this.logOutcome || undefined,
      client: this.clientIp() || undefined,
      method: this.logMethod || undefined,
      status: this.logStatus || undefined,
      hours: this.logHours,
    };
  }
  /** Older requests were added by scrolling: the live refresh would replace them with the newest ones, so it waits (the notice offers the way back). */
  paged = false;
  /** Infinite scroll of the sites: the next 50. */
  private async moreGroups() {
    if (this.logBusy || this.groups().length >= this.gCount()) return;
    this.logBusy = true;
    const seq = this.logSeq;
    try {
      const res = await this.api.invoke(proxyLogsGroupedRetrieve, { ...this.logParams(), ordering: this.ordering, limit: 50, offset: this.groups().length });
      if (seq === this.logSeq) { this.groups.update(x => [...x, ...res.results]); this.gCount.set(res.count); this.paged = true; }
    } catch (e) {
      console.warn('proxy log: next sites failed', e);
    } finally {
      this.logBusy = false;
    }
  }
  /** Opens or closes the requests of one site. */
  async toggleHost(g: ProxyLogGroup) {
    if (this.openHosts()[g.host]) { this.openHosts.update(({ [g.host]: _, ...rest }) => rest); return; }
    await this.fetchHost(g, undefined);
  }
  moreHost(g: ProxyLogGroup) { const o = this.openHosts()[g.host]; return this.fetchHost(g, o?.rows.at(-1)?.id); }
  private async fetchHost(g: ProxyLogGroup, before?: number) {
    const seq = this.logSeq;
    try {
      const res = await this.api.invoke(proxyLogsRetrieve, { ...this.logParams(), host: g.host, limit: 50, before });
      if (seq === this.logSeq) { this.openHosts.update(x => ({ ...x, [g.host]: { count: res.count, rows: [...(x[g.host]?.rows ?? []), ...res.results] } })); this.paged = true; }
    } catch (e) {
      console.warn('proxy log: requests of a site failed', e);
    }
  }
  /** Infinite scroll: the next 100 requests after the last one shown (keyset by id). */
  async more() {
    if (this.grouped) return this.moreGroups();
    const d = this.logsData();
    if (this.logBusy || !d.results.length || d.results.length >= d.count) return;
    this.logBusy = true;
    const seq = this.logSeq;
    try {
      const res = await this.api.invoke(proxyLogsRetrieve, { ...this.logParams(), before: d.results[d.results.length - 1].id, limit: 100 });
      if (seq === this.logSeq) { this.logsData.update(x => ({ ...x, count: res.count, results: [...x.results, ...res.results] })); this.paged = true; }
    } catch (e) {
      console.warn('proxy log: next page failed', e);
    } finally {
      this.logBusy = false;
    }
  }
  private logBusy = false; // a request is in flight: the poll skips its tick
  async loadLogs() {
    this.logBusy = true;
    const seq = ++this.logSeq; // an older answer (a slow poll) must not replace the one for the filters just chosen
    if (!this.logsLoaded()) this.api.invoke(statusRetrieve).then(st => this.status.set(st), () => {}); // for the empty log: is runproxy running
    try {
      if (this.grouped) {
        const [res, flat] = await Promise.all([
          this.api.invoke(proxyLogsGroupedRetrieve, { ...this.logParams(), ordering: this.ordering, limit: 50 }),
          this.api.invoke(proxyLogsRetrieve, { ...this.logParams(), limit: 1 }), // the totals of the header
        ]);
        if (seq === this.logSeq) { this.groups.set(res.results); this.gCount.set(res.count); this.logsData.set({ ...flat, results: [] }); this.openHosts.set({}); this.logsLoaded.set(true); this.paged = false; }
        return;
      }
      const res = await this.api.invoke(proxyLogsRetrieve, { ...this.logParams(), limit: 200 });
      if (seq === this.logSeq) { this.logsData.set(res); this.logsLoaded.set(true); this.paged = false; }
    } catch (e) {
      console.warn('proxy log refresh failed', e); // background poll: the list on screen stays
    } finally {
      this.logBusy = false;
    }
  }

  onFilterChange() {
    if (this.searchTimer) clearTimeout(this.searchTimer);
    this.searchTimer = setTimeout(() => this.filtersChanged(), 200);
  }
  /** Puts the filters in the address (only those not at their default); the query-parameter subscription then loads the log. */
  filtersChanged() {
    this.periodStore.remember(this.logHours);
    const queryParams = {
      outcome: this.logOutcome || null, q: this.logQ.trim() || null, detail: this.logDetail.trim() || null, method: this.logMethod || null, status: this.logStatus || null,
      client: this.logClient.trim() || null, hours: this.logHours === 24 ? null : this.logHours,
      group: this.grouped ? 1 : null, order: this.grouped && this.ordering === 'count' ? 'count' : null,
    };
    const cur = this.route.snapshot.queryParamMap;
    if (Object.entries(queryParams).every(([k, v]) => cur.get(k) === (v == null ? null : String(v)))) this.loadLogs(); // address unchanged (e.g. a method filter): no subscription event
    else this.router.navigate([], { relativeTo: this.route, queryParams, replaceUrl: true });
  }

  toggleLive() {
    this.syncPoll();
  }

  private syncPoll() {
    this.stopPoll();
    if (this.live && this.mode() === 'logs') {
      this.pollTimer = setInterval(() => { if (!document.hidden && !this.logBusy && !this.paged) this.loadLogs(); }, 3000);
    }
  }

  private stopPoll() {
    if (this.pollTimer) {
      clearInterval(this.pollTimer);
      this.pollTimer = undefined;
    }
  }

  purgeLogs() { this.pg()!.nativeElement.showModal(); this.previewPurge(); }

  previewPurge() {
    this.purgeCount.set(null);
    return this.ui.run(async () => {
      const r = await this.api.invoke(proxyLogsPurgeCreate, { body: { older_than_hours: this.purgeHours, dry_run: true } });
      this.purgeCount.set(r.deleted);
    });
  }

  doPurge() {
    const dlg = this.pg()!.nativeElement;
    return this.ui.run(async () => {
      dlg.close(); // no modal over a modal: the second factor is asked on its own
      try {
        const grant = await this.stepUp.request('log-purge', `Delete ${this.purgeCount()} proxy requests`, 'Delete requests');
        if (grant === null) { dlg.showModal(); return; }
        await this.api.invoke(proxyLogsPurgeCreate, { body: { older_than_hours: this.purgeHours, dry_run: false }, 'X-MFA-Grant': grant || undefined });
      } catch (e) { dlg.showModal(); throw e; }
      await this.loadLogs();
    }, { ok: `Deleted ${this.purgeCount()} proxy requests` });
  }

  isHostAllowed(host: string) {
    const h = (host || '').toLowerCase();
    if (this.allowedNow().has(h)) return true;
    const allowed = this.allowedDomains();
    const parts = h.split('.');
    for (let i = 0; i < parts.length; i++) {
      if (allowed.has(parts.slice(i).join('.'))) return true;
    }
    return false;
  }

  /** Runs `call` without a grant; when the server asks for a second factor (HTTPS inspection, WPAD, proxy address or port, a new Root CA)
   * asks for it once and runs `call` again with the grant. null when the user cancels. */
  private async withGrant<T>(call: (grant?: string) => Promise<T>): Promise<T | null> {
    try {
      return await call();
    } catch (e: any) {
      if (e?.status !== 403 || !e?.error?.mfa_required) throw e;
    }
    const grant = await this.stepUp.request('proxy-change', 'Change the proxy settings', 'Save settings');
    if (grant === null) return null;
    return call(grant || undefined);
  }

  /** Allows the site wherever it is blocked now: a personal allow entry when the DNS blacklist blocks it (DNS and proxy both), an @@host rule when
   * a proxy rule does (or nothing blocks it: then the site is no longer filtered nor inspected). Undo takes back exactly that. */
  allowHost(row: ProxyLog) {
    const host = (row.host || '').trim().toLowerCase();
    if (!host || this.isHostAllowed(host)) return;
    return this.ui.run(async () => {
      const done = await this.api.invoke(proxyAllowCreate, { body: { host, url: row.url || undefined } });
      await this.allowed(done, true);
      const where = done.dns_id ? 'in DNS and the proxy' : done.proxy_rule ? 'through the proxy' : ''; // a DNS exception lets the proxy through too
      if (!where) { this.ui.toast(`${host} is already allowed`); return; }
      this.ui.toast(`Allowed ${host} ${where}${done.note ? '. ' + done.note : ''}`, async () => {
        await this.api.invoke(proxyAllowUndoCreate, { body: done });
        await this.allowed(done, false);
      });
    });
  }
  /** Shows the outcome of Allow (or of its undo): the button state, and the proxy rules as the server now has them (unsaved edits of other fields stay). */
  private async allowed(done: ProxyAllow, on: boolean) {
    const now = new Set(this.allowedNow());
    if (done.dns_id) { if (on) now.add(done.host); else now.delete(done.host); }
    this.allowedNow.set(now);
    if (done.proxy_rule) {
      const rules = (await this.api.invoke(proxySettingsRetrieve)).PROXY_CUSTOM_RULES;
      this.cfg.update(c => ({ ...c, PROXY_CUSTOM_RULES: rules }));
      this.savedCfg = { ...this.savedCfg, PROXY_CUSTOM_RULES: rules };
    }
  }

  copy(url: string) { navigator.clipboard?.writeText(url).then(() => this.copied.set(url), () => {}); }

  dirty() { return changed(this.savedCfg, this.cfg()).length > 0; }
  /** The list of ad-block lists was edited and not saved yet: syncing must save it first, and says so on the button. */
  listsDirty() { return changed(this.savedCfg, this.cfg()).includes('PROXY_RULE_LISTS'); }

  save() {
    if (!this.savedCfg.PROXY_HTTPS_MITM && this.cfg().PROXY_HTTPS_MITM) {
      this.ui.ask('Turn on HTTPS inspection?', 'The proxy decrypts the HTTPS pages of every device that uses it, to filter them. '
        + 'Each device must trust the proxy’s Root CA, or secure sites show certificate errors. Sites with an @@ rule are never inspected.',
        () => this.doSave(), 'Turn on inspection');
      return undefined;
    }
    return this.doSave();
  }
  private async saveCfg() {
    this.errs.set({});
    try {
      const updated = await this.withGrant(g => this.api.invoke(proxySettingsPartialUpdate, { body: this.cfg(), 'X-MFA-Grant': g }));
      if (updated === null) return false;
      this.cfg.set(updated);
      this.savedCfg = structuredClone(updated);
      this.info.set(await this.api.invoke(proxyInfoRetrieve));
      return true;
    } catch (e) { this.errs.set(fieldErrors(e)); throw e; }
  }
  private doSave() {
    return this.ui.run(async () => { if (await this.saveCfg()) this.ui.toast('Proxy settings saved; the proxy applies them within 2 seconds'); });
  }

  /** Downloads the ad-block lists now. Unsaved edits of the list are saved first (the button then reads "Save and sync"); other unsaved settings are not sent. */
  syncRules() {
    return this.ui.run(async () => {
      this.syncing.set(true);
      try {
        if (this.listsDirty()) {
          const updated = await this.withGrant(g => this.api.invoke(proxySettingsPartialUpdate, { body: { PROXY_RULE_LISTS: this.cfg().PROXY_RULE_LISTS }, 'X-MFA-Grant': g }));
          if (updated === null) return;
          this.savedCfg = { ...this.savedCfg, PROXY_RULE_LISTS: updated.PROXY_RULE_LISTS };
        }
        const rules = await this.api.invoke(proxyRulesCreate);
        this.rules.set(rules);
        const bad = rules.filter(r => r.error).length;
        this.ui.toast(bad ? `Synced ${rules.length - bad} of ${rules.length} lists; ${bad} could not be downloaded` : `Synced ${rules.length} ${rules.length === 1 ? 'list' : 'lists'}`);
      } finally { this.syncing.set(false); }
    });
  }

  downloadCa() {
    const pem = this.info()?.pem;
    if (pem) saveFile(pem, 'zones-proxy-ca.crt', 'application/x-x509-ca-cert');
  }

  regenerateCa() {
    this.ui.ask(
      'Make a new Root CA?',
      'Every device that trusts the current one must install the new one. Until then, HTTPS inspection makes secure sites show certificate errors on those devices.',
      () =>
        this.ui.run(async () => {
          const info = await this.withGrant(g => this.api.invoke(proxyInfoCreate, { 'X-MFA-Grant': g }));
          if (info !== null) { this.info.set(info); this.ui.toast('New Root CA made: install it again on your devices'); }
        }),
      'Make new Root CA',
    );
  }

  runTest() {
    const u = this.testUrl.trim();
    if (!u) return;
    return this.ui.run(async () => {
      this.testResult.set(await this.api.invoke(proxyTestCreate, { body: { url: u } }));
    });
  }

  when(iso?: string) {
    return iso ? new Date(iso).toLocaleDateString() : '';
  }

  whenTime(iso?: string) {
    return iso ? new Date(iso).toLocaleTimeString() : '';
  }
  /** Time of a request: the date too when it is not today. */
  whenLog(iso: string) {
    const d = new Date(iso);
    return d.toDateString() === new Date().toDateString() ? d.toLocaleTimeString() : d.toLocaleString();
  }

  /** The outcome chip: its own word and the state colour (blocked red, error amber, filtered blue, allowed green). */
  outcomeColour(outcome: string) {
    return ({ blocked: 'blocked', error: 'error', timeout: 'error', filtered: 'forwarded' } as Record<string, string>)[outcome] ?? 'local';
  }
  outcomeLabel(outcome: string) {
    return ({ blocked: 'Blocked', error: 'Error', timeout: 'Timeout', filtered: 'Filtered', allowed: 'Allowed' } as Record<string, string>)[outcome] ?? outcome;
  }
}
