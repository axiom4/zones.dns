import { Component, OnDestroy, computed, effect, inject, input, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { Api } from '../api/api';
import {
  dhcpProxyInfoCreate,
  dhcpProxyInfoRetrieve,
  dhcpProxyLogsPurgeCreate,
  dhcpProxyLogsRetrieve,
  dhcpProxyTestCreate,
  dhcpSettingsPartialUpdate,
  dhcpSettingsRetrieve,
} from '../api/functions';
import { DhcpSettings, ProxyInfo, ProxyLog, ProxyLogsResponse, ProxyTestResult } from '../api/models';
import { Ui } from '../services/ui';

@Component({
  selector: 'app-dhcp-proxy',
  imports: [FormsModule, RouterLink],
  templateUrl: './dhcp-proxy.html',
})
export class DhcpProxy implements OnDestroy {
  private api = inject(Api);
  private ui = inject(Ui);
  mode = input<'settings' | 'logs'>('settings');
  cfg = signal<DhcpSettings>({});
  info = signal<ProxyInfo | null>(null);
  saved = signal(false);
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
      const [cfg, info] = await Promise.all([
        this.api.invoke(dhcpSettingsRetrieve),
        this.api.invoke(dhcpProxyInfoRetrieve),
      ]);
      this.cfg.set(cfg);
      this.info.set(info);
      if (this.mode() === 'logs') {
        await this.loadLogs();
      }
    });
  }

  async loadLogs() {
    try {
      const res = await this.api.invoke(dhcpProxyLogsRetrieve, {
        q: this.logQ.trim() || undefined,
        outcome: this.logOutcome || undefined,
        client: this.logClient.trim() || undefined,
        method: this.logMethod || undefined,
        hours: this.logHours,
        limit: 200,
      });
      this.logsData.set(res);
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
      this.pollTimer = setInterval(() => this.loadLogs(), 3000);
    }
  }

  private stopPoll() {
    if (this.pollTimer) {
      clearInterval(this.pollTimer);
      this.pollTimer = undefined;
    }
  }

  purgeLogs() {
    this.ui.ask(
      'Clear proxy logs?',
      'This removes all recorded HTTP/HTTPS proxy log entries.',
      () =>
        this.ui.run(async () => {
          await this.api.invoke(dhcpProxyLogsPurgeCreate, { body: { older_than_hours: 0 } });
          await this.loadLogs();
        }),
    );
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

  allowHost(row: ProxyLog) {
    const host = (row.host || '').trim().toLowerCase();
    if (!host || this.isHostAllowed(host)) return;
    return this.ui.run(async () => {
      const cur = (this.cfg().PROXY_CUSTOM_RULES || '').trim();
      const nextRules = cur ? `${cur}\n@@${host}` : `@@${host}`;
      const updated = await this.api.invoke(dhcpSettingsPartialUpdate, {
        body: { PROXY_CUSTOM_RULES: nextRules },
      });
      this.cfg.set(updated);
    });
  }

  save() {
    this.saved.set(false);
    return this.ui.run(async () => {
      const updated = await this.api.invoke(dhcpSettingsPartialUpdate, { body: this.cfg() });
      this.cfg.set(updated);
      this.info.set(await this.api.invoke(dhcpProxyInfoRetrieve));
      this.saved.set(true);
    });
  }

  downloadCa() {
    const pem = this.info()?.pem;
    if (!pem) return;
    const blob = new Blob([pem], { type: 'application/x-x509-ca-cert' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'zones-proxy-ca.crt';
    a.click();
    URL.revokeObjectURL(url);
  }

  regenerateCa() {
    this.ui.ask(
      'Regenerate Proxy Root CA?',
      'Clients using HTTPS MITM inspection will need to install the new Root CA certificate.',
      () =>
        this.ui.run(async () => {
          this.info.set(await this.api.invoke(dhcpProxyInfoCreate));
        }),
    );
  }

  runTest() {
    const u = this.testUrl.trim();
    if (!u) return;
    return this.ui.run(async () => {
      this.testResult.set(await this.api.invoke(dhcpProxyTestCreate, { body: { url: u } }));
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
