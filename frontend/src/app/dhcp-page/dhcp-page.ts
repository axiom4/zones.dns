import { Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Api } from '../api/api';
import { dhcpLeasesDestroy, dhcpLeasesList, dhcpSettingsPartialUpdate, dhcpSettingsRetrieve } from '../api/functions';
import { DhcpLease, DhcpSettings } from '../api/models';
import { Ui } from '../services/ui';

@Component({
  selector: 'app-dhcp-page',
  imports: [FormsModule],
  templateUrl: './dhcp-page.html',
})
export class DhcpPage {
  private api = inject(Api);
  private ui = inject(Ui);
  leases = signal<DhcpLease[]>([]);
  cfg = signal<DhcpSettings>({});
  showSettings = signal(false);
  saved = signal(false);
  q = '';
  all = false;

  constructor() { this.load(); }

  load() {
    return this.ui.run(async () => {
      const [leases, cfg] = await Promise.all([
        this.api.invoke(dhcpLeasesList, { q: this.q || undefined, all: this.all || undefined }),
        this.api.invoke(dhcpSettingsRetrieve),
      ]);
      this.leases.set(leases);
      this.cfg.set(cfg);
    });
  }
  saveSettings() {
    this.saved.set(false);
    return this.ui.run(async () => {
      this.cfg.set(await this.api.invoke(dhcpSettingsPartialUpdate, { body: this.cfg() }));
      this.saved.set(true);
    });
  }
  when(iso: string) { return new Date(iso).toLocaleString(); }
  end(l: DhcpLease) {
    this.ui.ask(`End the lease of ${l.address}?`, 'The address is free again. The client keeps using it until it renews, and is then told it cannot.', () =>
      this.ui.run(async () => { await this.api.invoke(dhcpLeasesDestroy, { family: l.family, id: l.id }); await this.load(); }));
  }
}
