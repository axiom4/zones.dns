import { Component, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Api } from '../api/api';
import { hostsCreate, hostsDestroy, hostsList, hostsPartialUpdate } from '../api/functions';
import { StaticHost } from '../api/models';
import { Ui } from '../services/ui';

@Component({
  selector: 'app-hosts-page',
  imports: [FormsModule],
  templateUrl: './hosts-page.html',
})
export class HostsPage {
  private api = inject(Api);
  private ui = inject(Ui);
  hosts = signal<StaticHost[]>([]);
  filter = signal('');
  shown = computed(() => { const q = this.filter().trim().toLowerCase(); return q ? this.hosts().filter(h => (h.name + ' ' + h.address + ' ' + (h.note ?? '')).toLowerCase().includes(q)) : this.hosts(); });
  draft = { name: '', address: '', ttl: null as number | null, note: '' };
  editing = signal<number | null>(null);
  edit = { name: '', address: '', ttl: 300 as number | null, note: '' };

  constructor() { this.load(); }

  load() { return this.ui.run(async () => this.hosts.set(await this.api.invoke(hostsList))); }
  add() {
    const { ttl, ...rest } = this.draft;
    return this.ui.run(async () => {
      await this.api.invoke(hostsCreate, { body: { ...rest, ...(ttl != null ? { ttl } : {}) } });
      this.draft = { name: '', address: '', ttl: null, note: '' };
      await this.load();
    });
  }
  startEdit(h: StaticHost) { this.edit = { name: h.name, address: h.address, ttl: h.ttl ?? 300, note: h.note ?? '' }; this.editing.set(h.id); }
  save(h: StaticHost) {
    return this.ui.run(async () => {
      await this.api.invoke(hostsPartialUpdate, { id: h.id, body: { ...this.edit, ttl: this.edit.ttl ?? 300 } });
      this.editing.set(null);
      await this.load();
    });
  }
  toggle(h: StaticHost) {
    return this.ui.run(async () => { await this.api.invoke(hostsPartialUpdate, { id: h.id, body: { enabled: h.enabled === false } }); await this.load(); });
  }
  del(h: StaticHost) {
    this.ui.ask(`Delete ${h.name} → ${h.address}?`, 'The name will be answered by the zones, the blacklist or the upstream again.', () =>
      this.ui.run(async () => { await this.api.invoke(hostsDestroy, { id: h.id }); await this.load(); }));
  }
}
