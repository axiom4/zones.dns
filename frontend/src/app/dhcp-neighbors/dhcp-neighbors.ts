import { Component, computed, inject, signal, viewChild } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Api } from '../api/api';
import { dhcpNeighborsList } from '../api/functions';
import { DhcpNeighbor } from '../api/models';
import { PingLive } from '../ping-live/ping-live';
import { Ping } from '../services/ping';
import { Ui } from '../services/ui';

type Host = { mac: string; vendor: string; hostname: string; addrs: DhcpNeighbor[] };
const KIND: Record<string, string> = { dhcpv6: 'DHCPv6 lease', slaac: 'SLAAC', other: 'privacy / fixed', 'link-local': 'link-local' };

@Component({
  selector: 'app-dhcp-neighbors',
  imports: [FormsModule, PingLive],
  templateUrl: './dhcp-neighbors.html',
})
export class DhcpNeighbors {
  private api = inject(Api);
  private ui = inject(Ui);
  ping = inject(Ping);
  live = viewChild.required(PingLive);
  items = signal<DhcpNeighbor[]>([]);
  filter = signal('');
  loaded = signal(false);
  /** One row per host (MAC address): the same host has a DHCPv6 address, a SLAAC one, privacy ones and a link-local one. */
  hosts = computed(() => {
    const q = this.filter().trim().toLowerCase();
    const by = new Map<string, Host>();
    for (const n of this.items()) {
      const h = by.get(n.mac) ?? { mac: n.mac, vendor: n.vendor, hostname: n.hostname, addrs: [] };
      h.addrs.push(n);
      by.set(n.mac, h);
    }
    const all = [...by.values()];
    return q ? all.filter(h => `${h.mac} ${h.vendor} ${h.hostname} ${h.addrs.map(a => `${a.address} ${KIND[a.kind]}`).join(' ')}`.toLowerCase().includes(q)) : all;
  });
  /** The addresses worth pinging: not link-local (those answer only on the link, and from here that proves little). */
  global = (h: Host) => h.addrs.filter(a => a.kind !== 'link-local');
  kind = (n: DhcpNeighbor) => KIND[n.kind] ?? n.kind;

  constructor() { this.load(); }

  load() { return this.ui.run(async () => { this.items.set(await this.api.invoke(dhcpNeighborsList)); this.loaded.set(true); }); }
  watch(a: DhcpNeighbor) { this.live().open(a.address); }
  pingOne(a: DhcpNeighbor) { return this.ui.run(() => this.ping.once(a.address)); }
  pingAll() { return this.ui.run(() => this.ping.run(this.items().filter(n => n.kind !== 'link-local').map(n => n.address))); }
}
