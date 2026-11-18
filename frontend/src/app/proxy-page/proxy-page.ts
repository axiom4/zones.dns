import { Component, ElementRef, OnDestroy, computed, effect, inject, input, signal, viewChild } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
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
import { StepUp } from '../services/step-up';
import { Ui, saveFile } from '../services/ui';

@Component({
  selector: 'app-proxy-page',
  imports: [FormsModule, RouterLink],
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
  info = signal<ProxyInfo | null>(null);
  saved = signal(false);
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

  constructor() {
    this.load();
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
      this.info.set(info);
      this.rules.set(rules);
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
      if (seq === this.logSeq) this.logsData.set(res);
    } catch {
      /* background poll ignore */
    }
  }

  onFilterChange() {
    if (this.searchTimer) clearTimeout(this.searchTimer);
    this.searchTimer = setTimeout(() => this.loadLogs(), 200);
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

  purgeLogs() { this.ui.error.set(''); this.pg()!.nativeElement.showModal(); this.previewPurge(); }

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
        const grant = await this.stepUp.request('log-purge');
        if (grant === null) { dlg.showModal(); return; }
        await this.api.invoke(proxyLogsPurgeCreate, { body: { older_than_hours: this.purgeHours, dry_run: false }, 'X-MFA-Grant': grant || undefined });
      } catch (e) { dlg.showModal(); throw e; }
      await this.loadLogs();
    });
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
    const grant = await this.stepUp.request('proxy-change');
    if (grant === null) return null;
    return call(grant || undefined);
  }

  allowHost(row: ProxyLog) {
    const host = (row.host || '').trim().toLowerCase();
    if (!host || this.isHostAllowed(host)) return;
    return this.ui.run(async () => {
      const cur = (this.cfg().PROXY_CUSTOM_RULES || '').trim();
      const nextRules = cur ? `${cur}\n@@${host}` : `@@${host}`;
      const updated = await this.api.invoke(proxySettingsPartialUpdate, {
        body: { PROXY_CUSTOM_RULES: nextRules },
      });
      this.cfg.set(updated);
    });
  }

  save() {
    this.saved.set(false);
    return this.ui.run(async () => {
      const updated = await this.withGrant(g => this.api.invoke(proxySettingsPartialUpdate, { body: this.cfg(), 'X-MFA-Grant': g }));
      if (updated === null) return;
      this.cfg.set(updated);
      this.info.set(await this.api.invoke(proxyInfoRetrieve));
      this.saved.set(true);
    });
  }

  syncRules() {
    return this.ui.run(async () => {
      const updated = await this.withGrant(g => this.api.invoke(proxySettingsPartialUpdate, { body: this.cfg(), 'X-MFA-Grant': g }));
      if (updated === null) return;
      this.cfg.set(updated);
      this.rules.set(await this.api.invoke(proxyRulesCreate));
    });
  }

  downloadCa() {
    const pem = this.info()?.pem;
    if (pem) saveFile(pem, 'zones-proxy-ca.crt', 'application/x-x509-ca-cert');
  }

  regenerateCa() {
    this.ui.ask(
      'Regenerate Proxy Root CA?',
      'Clients using HTTPS MITM inspection will need to install the new Root CA certificate.',
      () =>
        this.ui.run(async () => {
          const info = await this.withGrant(g => this.api.invoke(proxyInfoCreate, { 'X-MFA-Grant': g }));
          if (info !== null) this.info.set(info);
        }),
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

  badgeType(outcome: string) {
    if (outcome === 'blocked') return 'TXT';
    if (outcome === 'filtered') return 'CAA';
    if (outcome === 'error') return 'MX';
    return 'A';
  }
}
