import { Component, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Api } from './api/api';
import { hostsCreate, hostsDestroy, hostsList, hostsPartialUpdate } from './api/functions';
import { StaticHost } from './api/models';
import { Ui } from './ui';

@Component({
  selector: 'app-hosts-page',
  imports: [FormsModule],
  template: `
    <header>
      <div>
        <h2>Hosts</h2>
        <p class="soft">{{ hosts().length }} {{ hosts().length === 1 ? 'static host' : 'static hosts' }}. Like a hosts file: the name is answered with the address set here, whatever the real DNS says. It wins over zones, the blacklist and the upstream.</p>
      </div>
      @if (hosts().length > 5) {
        <div class="actions"><input class="search" type="search" [ngModel]="filter()" (ngModelChange)="filter.set($event)" name="f" placeholder="Search hosts" aria-label="Search hosts" autocomplete="off"></div>
      }
    </header>
    <form class="composer" (ngSubmit)="add()">
      <input class="grow" name="n" [(ngModel)]="draft.name" placeholder="host name, e.g. nas.lan" autocomplete="off" aria-label="Host name" required>
      <input name="a" [(ngModel)]="draft.address" placeholder="IP address, e.g. 192.168.1.50" autocomplete="off" aria-label="IP address" required>
      <input class="ttl" name="t" type="number" min="0" [(ngModel)]="draft.ttl" placeholder="TTL" aria-label="TTL in seconds">
      <input class="note" name="o" [(ngModel)]="draft.note" placeholder="Note (optional)" autocomplete="off" aria-label="Note">
      <button class="primary">Add host</button>
    </form>
    <ul class="records">
      @for (h of shown(); track h.id) {
        @if (editing() === h.id) {
          <li class="editing">
            <form class="composer inline-edit" (ngSubmit)="save(h)">
              <input class="grow" name="en" [(ngModel)]="edit.name" autocomplete="off" aria-label="Host name" required>
              <input name="ea" [(ngModel)]="edit.address" autocomplete="off" aria-label="IP address" required>
              <input class="ttl" name="et" type="number" min="0" [(ngModel)]="edit.ttl" aria-label="TTL in seconds">
              <input class="note" name="eo" [(ngModel)]="edit.note" autocomplete="off" aria-label="Note">
              <button class="mini primary">Save</button>
              <button type="button" class="mini" (click)="editing.set(null)">Cancel</button>
            </form>
          </li>
        } @else {
          <li [class.off]="h.enabled === false">
            <span class="type" [attr.data-t]="h.address.includes(':') ? 'AAAA' : 'A'">{{ h.address.includes(':') ? 'AAAA' : 'A' }}</span>
            <span class="rname">{{ h.name }}@if (h.note) {<small class="note-t">{{ h.note }}</small>}</span>
            <span class="rvalue">{{ h.address }}</span>
            <span class="ttlv">{{ h.ttl }}s</span>
            <button class="switch" role="switch" [attr.aria-checked]="h.enabled !== false" (click)="toggle(h)"
                    [title]="h.enabled === false ? 'Disabled: click to enable' : 'Enabled: click to disable'"><i></i></button>
            <button class="icon edit" (click)="startEdit(h)" [attr.aria-label]="'Edit ' + h.name">✎</button>
            <button class="icon" (click)="del(h)" [attr.aria-label]="'Delete ' + h.name">✕</button>
          </li>
        }
      } @empty {
        <li class="empty">{{ hosts().length ? 'No results for your search.' : 'No static hosts. Add one above: queries for that name get your address.' }}</li>
      }
    </ul>
`,
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
