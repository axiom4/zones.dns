import { Component, ElementRef, OnDestroy, computed, effect, inject, input, signal, viewChild } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, Router, RouterLink, RouterLinkActive } from '@angular/router';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { Api } from '../api/api';
import {
  proxyInfoCreate,
  proxyInfoRetrieve,
  proxyRulesCreate,
  proxyRulesList,
  proxyLogsPurgeCreate,
  proxyLogsRetrieve,
  proxyTestCreate,
  proxySettingsPartialUpdate,
  proxySettingsRetrieve,
} from '../api/functions';
import { ProxyRuleList, ProxySettings, ProxyInfo, ProxyLog, ProxyLogsResponse, ProxyTestResult } from '../api/models';
import { fieldErrors } from '../lib/error-text';
import { SettingField, SettingsFields, changed } from '../dhcp-page/settings-fields';
import { StepUp } from '../services/step-up';
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
  { key: 'PROXY_CUSTOM_RULES', kind: 'textarea', label: 'Your own rules', ph: '##.sponsored-box\nexample.com##.promo-modal\n/custom-ad-banner/\n@@bank.example.com',
    help: 'One per line. ##selector hides page parts (example.com##selector: on one site only); text or /regex/ blocks addresses; @@site.com never filters nor inspects that site.' },
];
const LISTS: SettingField[] = [
  { key: 'PROXY_RULE_LISTS', kind: 'textarea', label: 'Ad-block lists', term: 'EasyList format', ph: 'easylist=https://easylist.to/easylist/easylist.txt\neasyprivacy=https://easylist.to/easylist/easyprivacy.txt',
    help: 'One name=https://… per line, downloaded every day. A list that fails keeps its last good rules.' },
];

@Component({
  selector: 'app-proxy-page',
  imports: [FormsModule, RouterLink, RouterLinkActive, SettingsFields],
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
  readonly lists = LISTS;
  rules = signal<ProxyRuleList[]>([]);
  testUrl = '';
  testResult = signal<ProxyTestResult | null>(null);

  logsData = signal<ProxyLogsResponse>({
    count: 0,
    blocked_count: 0,
    filtered_count: 0,
    clients: [],
    results: [],
  });
  logQ = '';
  logOutcome: '' | 'allowed' | 'filtered' | 'blocked' | 'error' = '';
  logClient = '';
  logMethod = '';
  logHours = 24;
  live = true;
  private pollTimer?: ReturnType<typeof setInterval>;
  private searchTimer?: ReturnType<typeof setTimeout>;

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

  constructor() {
    this.load();
    // the log filters live in the address (?outcome=&q=&client=&hours=): links from Statistics land filtered, Back and reload keep them
    this.route.queryParamMap.pipe(takeUntilDestroyed()).subscribe(p => {
      const o = p.get('outcome') ?? '', h = Number(p.get('hours') ?? 24);
      this.logOutcome = (['allowed', 'filtered', 'blocked', 'error'].includes(o) ? o : '') as typeof this.logOutcome;
      this.logQ = p.get('q') ?? '';
      this.logClient = p.get('client') ?? '';
      this.logHours = [1, 24, 168, 0].includes(h) ? h : 24;
      if (this.mode() === 'logs') this.loadLogs();
    });
    effect(() => {
      if (this.mode() === 'logs') {
        this.loadLogs();
        this.syncPoll();
      } else {
        this.stopPoll();
      }
    });
  }

  ngOnDestroy() {
    this.stopPoll();
    if (this.searchTimer) clearTimeout(this.searchTimer);
  }

  load() {
    return this.ui.run(async () => {
      const [cfg, info, rules] = await Promise.all([
        this.api.invoke(proxySettingsRetrieve),
        this.api.invoke(proxyInfoRetrieve),
        this.api.invoke(proxyRulesList),
      ]);
      this.cfg.set(cfg);
      this.savedCfg = structuredClone(cfg);
      this.info.set(info);
      this.rules.set(rules);
      this.loaded.set(true);
    });
  }

  private logSeq = 0;
  async loadLogs() {
    const seq = ++this.logSeq; // an older answer (a slow poll) must not replace the one for the filters just chosen
    try {
      const res = await this.api.invoke(proxyLogsRetrieve, {
        q: this.logQ.trim() || undefined,
        outcome: this.logOutcome || undefined,
        client: this.logClient.trim() || undefined,
        method: this.logMethod || undefined,
        hours: this.logHours,
        limit: 200,
      });
      if (seq === this.logSeq) { this.logsData.set(res); this.logsLoaded.set(true); }
    } catch {
      /* background poll ignore */
    }
  }

  onFilterChange() {
    if (this.searchTimer) clearTimeout(this.searchTimer);
    this.searchTimer = setTimeout(() => this.filtersChanged(), 200);
  }
  /** Puts the filters in the address (only those not at their default); the query-parameter subscription then loads the log. */
  filtersChanged() {
    const queryParams = {
      outcome: this.logOutcome || null, q: this.logQ.trim() || null, client: this.logClient || null, hours: this.logHours === 24 ? null : this.logHours,
    };
    this.router.navigate([], { relativeTo: this.route, queryParams, replaceUrl: true });
    this.loadLogs(); // also when the address does not change (e.g. a method filter, which is not kept in it)
  }

  toggleLive() {
    this.syncPoll();
  }

  private syncPoll() {
    this.stopPoll();
    if (this.live && this.mode() === 'logs') {
      this.pollTimer = setInterval(() => { if (!document.hidden) this.loadLogs(); }, 3000);
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

  /** Adds an @@host exception (no filtering, no HTTPS inspection for that site); Undo puts the rules back as they were. */
  allowHost(row: ProxyLog) {
    const host = (row.host || '').trim().toLowerCase();
    if (!host || this.isHostAllowed(host)) return;
    const setRules = async (rules: string) => {
      const updated = await this.api.invoke(proxySettingsPartialUpdate, { body: { PROXY_CUSTOM_RULES: rules } });
      this.cfg.set(updated);
      this.savedCfg = structuredClone(updated);
    };
    return this.ui.run(async () => {
      const before = this.cfg().PROXY_CUSTOM_RULES || '';
      await setRules(before.trim() ? `${before.trim()}\n@@${host}` : `@@${host}`);
      this.ui.toast(`Allowed ${host} through the proxy`, () => setRules(before));
    });
  }

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
    return ({ blocked: 'blocked', error: 'error', filtered: 'forwarded' } as Record<string, string>)[outcome] ?? 'local';
  }
  outcomeLabel(outcome: string) {
    return ({ blocked: 'Blocked', error: 'Error', filtered: 'Filtered', allowed: 'Allowed' } as Record<string, string>)[outcome] ?? outcome;
  }
}
