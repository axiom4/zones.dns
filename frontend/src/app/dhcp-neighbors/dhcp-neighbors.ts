import { Component, computed, inject, signal, viewChild } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Api } from '../api/api';
import { dhcpNeighborsList } from '../api/functions';
import { DhcpNeighbor } from '../api/models';
import { PingLive } from '../ping-live/ping-live';
import { Ping } from '../services/ping';
import { Ui } from '../services/ui';

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
  shown = computed(() => {
    const q = this.filter().trim().toLowerCase();
    return q ? this.items().filter(n => `${n.address} ${n.mac} ${n.vendor} ${n.hostname} ${KIND[n.kind]}`.toLowerCase().includes(q)) : this.items();
  });
  kind = (n: DhcpNeighbor) => KIND[n.kind] ?? n.kind;

  constructor() { this.load(); }

  load() { return this.ui.run(async () => { this.items.set(await this.api.invoke(dhcpNeighborsList)); this.loaded.set(true); }); }
  watch(n: DhcpNeighbor) { this.live().open(n.address); }
  pingOne(n: DhcpNeighbor) { return this.ui.run(() => this.ping.once(n.address)); }
  pingAll() { return this.ui.run(() => this.ping.run(this.items().filter(n => n.kind !== 'link-local').map(n => n.address))); }
}
