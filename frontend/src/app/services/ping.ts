import { Injectable, inject, signal } from '@angular/core';
import { Api } from '../api/api';
import { dhcpPingCreate } from '../api/functions';
import { DhcpPingResult } from '../api/models';

/** Pings hosts of the network from the server and remembers the last answer of each address. */
@Injectable({ providedIn: 'root' })
export class Ping {
  private api = inject(Api);
  results = signal<Record<string, DhcpPingResult>>({});
  busy = signal(false);

  async run(addresses: string[]) {
    const list = [...new Set(addresses.filter(a => !!a))];
    this.busy.set(true);
    try {
      for (let i = 0; i < list.length; i += 64) { // the server takes 64 at a time
        const out = await this.api.invoke(dhcpPingCreate, { body: { addresses: list.slice(i, i + 64) } });
        this.results.update(r => ({ ...r, ...Object.fromEntries(out.map(x => [x.address, x])) }));
      }
    } finally { this.busy.set(false); }
  }
  label(address: string) {
    const r = this.results()[address];
    return !r ? '' : r.error ? r.error : r.up ? `up${r.ms != null ? ' ' + r.ms + ' ms' : ''}` : 'no answer';
  }
}
