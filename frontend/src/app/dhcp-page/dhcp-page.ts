import { Component, computed, inject, input, signal, viewChild } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Router, RouterLink } from '@angular/router';
import { Api } from '../api/api';
import { dhcpLeasesDestroy, dhcpReservationsList, dhcpReservations6List, dhcpLeasesList, dhcpSettingsPartialUpdate, dhcpSettingsRetrieve } from '../api/functions';
import { DhcpLease, DhcpSettings } from '../api/models';
import { byIp } from '../lib/ip';
import { DhcpReservations } from '../dhcp-reservations/dhcp-reservations';
import { DhcpNeighbors } from '../dhcp-neighbors/dhcp-neighbors';
import { DhcpReservations6 } from '../dhcp-reservations6/dhcp-reservations6';
import { PingLive } from '../ping-live/ping-live';
import { Ping } from '../services/ping';
import { StepUp } from '../services/step-up';
import { Ui } from '../services/ui';

@Component({
  selector: 'app-dhcp-page',
  imports: [FormsModule, RouterLink, DhcpReservations, DhcpReservations6, DhcpNeighbors, PingLive],
  templateUrl: './dhcp-page.html',
})
export class DhcpPage {
  private api = inject(Api);
  private ui = inject(Ui);
  private stepUp = inject(StepUp);
  ping = inject(Ping);
  live = viewChild(PingLive);
  leases = signal<DhcpLease[]>([]);
  cfg = signal<DhcpSettings>({});
  saved = signal(false);
  private router = inject(Router);
  section = input('leases', { alias: 'tab' }); // the :tab of the route /dhcp/:tab
  tab = computed(() => (['leases', 'leases6', 'reservations', 'reservations6', 'neighbors'].includes(this.section()) ? this.section() : 'leases'));
  shown = computed(() => this.leases().filter(l => l.family === (this.tab() === 'leases6' ? 6 : 4)));
  reserve = signal<{ mac: string; ip: string; hostname: string } | null>(null);
  reserve6 = signal<{ duid: string; ip: string } | null>(null);
  reserved = signal(new Set<string>()); // MACs and addresses that already have a reservation
  q = '';
  all = false;

  constructor() { this.load(); }

  load() {
    return this.ui.run(async () => {
      const [leases, cfg, res, res6] = await Promise.all([
        this.api.invoke(dhcpLeasesList, { q: this.q || undefined, all: this.all || undefined }),
        this.api.invoke(dhcpSettingsRetrieve),
        this.api.invoke(dhcpReservationsList),
        this.api.invoke(dhcpReservations6List),
      ]);
      this.leases.set([...leases].sort((a, b) => byIp(a.address, b.address)));
      this.reserved.set(new Set([...res.flatMap(r => [r.mac, r.ip]), ...res6.flatMap(r => [r.duid, r.ip])]));
      this.cfg.set(cfg);
    });
  }
  openSettings(dlg: HTMLDialogElement) { this.saved.set(false); dlg.showModal(); }
  saveSettings() {
    this.saved.set(false);
    return this.ui.run(async () => {
      // the gateway, DNS, routes, boot server, Leasequery... need a second factor (scope dhcp-change): asked only when the server says so
      const save = (g?: string) => this.api.invoke(dhcpSettingsPartialUpdate, { body: this.cfg(), 'X-MFA-Grant': g });
      let cfg: DhcpSettings;
      try {
        cfg = await save();
      } catch (e: any) {
        if (e?.status !== 403 || !e?.error?.mfa_required) throw e;
        const grant = await this.stepUp.request('dhcp-change');
        if (grant === null) return;
        cfg = await save(grant || undefined);
      }
      this.cfg.set(cfg);
      this.saved.set(true);
    });
  }
  /** Make the address of a DHCPv4 lease fixed for its client: opens the reservations with the form filled in. */
  fix(l: DhcpLease) {
    this.reserve.set({ mac: l.client, ip: l.address, hostname: l.hostname });
    this.router.navigate(['/dhcp', 'reservations']);
  }
  /** Make the address of a DHCPv6 lease fixed for its client (DUID): opens the DHCPv6 reservations with the form filled in. */
  fix6(l: DhcpLease) {
    this.reserve6.set({ duid: l.client, ip: l.address });
    this.router.navigate(['/dhcp', 'reservations6']);
  }
  watch(l: DhcpLease) { this.live()?.open(l.address); }
  pingOne(l: DhcpLease) { return this.ui.run(() => this.ping.once(l.address)); }
  pingAll() { return this.ui.run(() => this.ping.run(this.shown().filter(l => l.active && l.kind === 'address').map(l => l.address))); }
  isReserved(l: DhcpLease) { return this.reserved().has(l.client) || this.reserved().has(l.address); }
  when(iso: string) { return new Date(iso).toLocaleString(); }
  end(l: DhcpLease) {
    this.ui.ask(`End the lease of ${l.address}?`, 'The address is free again. The client keeps using it until it renews, and is then told it cannot.', () =>
      this.ui.run(async () => { await this.api.invoke(dhcpLeasesDestroy, { family: l.family, id: l.id }); await this.load(); }));
  }
}
