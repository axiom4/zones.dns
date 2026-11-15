import { Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Api } from '../api/api';
import {
  dhcpProxyInfoCreate,
  dhcpProxyInfoRetrieve,
  dhcpProxyTestCreate,
  dhcpSettingsPartialUpdate,
  dhcpSettingsRetrieve,
} from '../api/functions';
import { DhcpSettings, ProxyInfo, ProxyTestResult } from '../api/models';
import { Ui } from '../services/ui';

@Component({
  selector: 'app-dhcp-proxy',
  imports: [FormsModule],
  templateUrl: './dhcp-proxy.html',
})
export class DhcpProxy {
  private api = inject(Api);
  private ui = inject(Ui);
  cfg = signal<DhcpSettings>({});
  info = signal<ProxyInfo | null>(null);
  saved = signal(false);
  testUrl = '';
  testResult = signal<ProxyTestResult | null>(null);

  constructor() {
    this.load();
  }

  load() {
    return this.ui.run(async () => {
      const [cfg, info] = await Promise.all([
        this.api.invoke(dhcpSettingsRetrieve),
        this.api.invoke(dhcpProxyInfoRetrieve),
      ]);
      this.cfg.set(cfg);
      this.info.set(info);
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
}
