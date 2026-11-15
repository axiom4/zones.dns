import { Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Api } from '../api/api';
import { dhcpLeasesDestroy, dhcpReservationsList, dhcpLeasesList, dhcpSettingsPartialUpdate, dhcpSettingsRetrieve } from '../api/functions';
import { DhcpLease, DhcpSettings } from '../api/models';
import { byIp } from '../lib/ip';
import { DhcpReservations } from '../dhcp-reservations/dhcp-reservations';
import { Ping } from '../services/ping';
import { Ui } from '../services/ui';

@Component({
  selector: 'app-dhcp-page',
  imports: [FormsModule, DhcpReservations],
  templateUrl: './dhcp-page.html',
})
export class DhcpPage {
  private api = inject(Api);
  private ui = inject(Ui);
  ping = inject(Ping);
  leases = signal<DhcpLease[]>([]);
  cfg = signal<DhcpSettings>({});
  saved = signal(false);
  tab = signal<'leases' | 'reservations'>('leases');
  reserve = signal<{ mac: string; ip: string; hostname: string } | null>(null);
  reserved = signal(new Set<string>()); // MACs and addresses that already have a reservation
  q = '';
  all = false;

  constructor() { this.load(); }

  load() {
    return this.ui.run(async () => {
      const [leases, cfg, res] = await Promise.all([
        this.api.invoke(dhcpLeasesList, { q: this.q || undefined, all: this.all || undefined }),
        this.api.invoke(dhcpSettingsRetrieve),
        this.api.invoke(dhcpReservationsList),
      ]);
      this.leases.set([...leases].sort((a, b) => byIp(a.address, b.address)));
      this.reserved.set(new Set(res.flatMap(r => [r.mac, r.ip])));
      this.cfg.set(cfg);
    });
  }
  openSettings(dlg: HTMLDialogElement) { this.saved.set(false); dlg.showModal(); }
  saveSettings() {
    this.saved.set(false);
    return this.ui.run(async () => {
      this.cfg.set(await this.api.invoke(dhcpSettingsPartialUpdate, { body: this.cfg() }));
      this.saved.set(true);
    });
  }
  /** Make the address of a DHCPv4 lease fixed for its client: opens the reservations with the form filled in. */
  fix(l: DhcpLease) {
    this.reserve.set({ mac: l.client, ip: l.address, hostname: l.hostname });
    this.tab.set('reservations');
  }
  pingOne(l: DhcpLease) { return this.ui.run(() => this.ping.run([l.address])); }
  pingAll() { return this.ui.run(() => this.ping.run(this.leases().filter(l => l.active && l.kind === 'address').map(l => l.address))); }
  isReserved(l: DhcpLease) { return this.reserved().has(l.client) || this.reserved().has(l.address); }
  when(iso: string) { return new Date(iso).toLocaleString(); }
  end(l: DhcpLease) {
    this.ui.ask(`End the lease of ${l.address}?`, 'The address is free again. The client keeps using it until it renews, and is then told it cannot.', () =>
      this.ui.run(async () => { await this.api.invoke(dhcpLeasesDestroy, { family: l.family, id: l.id }); await this.load(); }));
  }
}
