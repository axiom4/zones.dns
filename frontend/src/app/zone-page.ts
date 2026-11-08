import { Component, ElementRef, computed, effect, inject, input, signal, untracked, viewChild } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Api } from './api/api';
import { recordsBulkCreate, recordsDestroy, recordsList, zonesExportRetrieve, zonesImportCreate, zonesSyncPtrCreate } from './api/functions';
import { ActionEnum, Record, ZoneImportResult } from './api/models';
import { RecordForm } from './record-form';
import { ptrToIp } from './reverse';
import { Ui } from './ui';
import { ZonesStore } from './zones-store';

@Component({
  selector: 'app-zone-page',
  imports: [FormsModule, RecordForm],
  template: `
    @if (zone(); as z) {
      <header>
        <div>
          <h2>{{ z.name }}</h2>
          <p class="soft">{{ records().length }} records</p>
        </div>
        <div class="actions">
          <input class="search" type="search" [(ngModel)]="filter" name="f" placeholder="Search name, type, value or note" aria-label="Search records">
          <select [ngModel]="sortBy()" (ngModelChange)="sortBy.set($event)" name="sb" aria-label="Sort records">
            <option value="">Sort: default</option>
            <option value="type">Sort: type</option>
            <option value="name">{{ z.reverse ? 'Sort: IP' : 'Sort: host' }}</option>
            <option value="value">{{ z.reverse ? 'Sort: host' : 'Sort: IP / value' }}</option>
            <option value="ttl">Sort: TTL</option>
          </select>
          @if (sortBy()) {
            <button class="ghost" (click)="desc.set(!desc())" [attr.aria-label]="desc() ? 'Descending' : 'Ascending'" [title]="desc() ? 'Descending' : 'Ascending'">{{ desc() ? '↓' : '↑' }}</button>
          }
          <button class="primary" (click)="form.open()">New record</button>
          <button class="ghost" (click)="openImport()">Import</button>
          <button class="ghost" (click)="exportZone()">Export</button>
        </div>
      </header>

      @if (z.reverse) {
        <div class="about rev">
          <p><b>Reverse zone</b> for the network <code>{{ z.cidr }}</code>. Here PTR records link an address to its name: the record name is the last part of the address (for <code>10.0.0.7</code> in a /24 it is <code>7</code>).</p>
          <div class="actions">
            <button class="ghost" (click)="syncPtr()">Generate PTR from A/AAAA records</button>
            @if (syncMsg()) { <span class="soft">{{ syncMsg() }}</span> }
          </div>
        </div>
      }

      <app-record-form #form [zoneId]="z.id" [zoneName]="z.name" [reverse]="z.reverse" [records]="records()" (saved)="onSaved($event)" />

      @if (selected().size) {
        <div class="bulk" role="toolbar" aria-label="Actions on the selected records">
          <b>{{ selected().size }} selected</b>
          <button class="mini" (click)="bulk('enable')">Enable</button>
          <button class="mini" (click)="bulk('disable')">Disable</button>
          <button class="mini danger-o" (click)="bulkDelete()">Delete</button>
          <button class="mini" (click)="selected.set(empty)">Deselect</button>
        </div>
      }

      <ul class="records">
        @if (shown().length) {
          <li class="head">
            <input type="checkbox" [checked]="allSelected()" (change)="toggleAll()" aria-label="Select all">
            <span class="soft">Select all</span>
          </li>
        }
        @for (r of shown(); track r.id) {
          <li [class.off]="r.enabled === false">
            <input type="checkbox" [checked]="selected().has(r.id)" (change)="toggle(r.id)" [attr.aria-label]="'Select ' + r.name">
            <span class="type" [attr.data-t]="r.type">{{ r.type }}</span>
            <span class="rname">{{ r.name }}@if (ipOf(r); as ip) {<small class="note-t">{{ ip }}</small>}</span>
            <span class="rvalue">{{ r.value }}@if (r.note) {<small class="note-t">{{ r.note }}</small>}</span>
            <span class="ttlv">{{ r.ttl }}s</span>
            <button class="switch" role="switch" [attr.aria-checked]="r.enabled !== false" (click)="toggleOne(r)"
                    [title]="r.enabled === false ? 'Disabled: click to enable' : 'Enabled: click to disable'"><i></i></button>
            <button class="icon edit" (click)="form.open(r)" [attr.aria-label]="'Edit ' + r.name">✎</button>
            <button class="icon" (click)="del(r)" [attr.aria-label]="'Delete ' + r.name">✕</button>
          </li>
        } @empty {
          <li class="empty">{{ records().length ? 'No results for your search.' : 'This zone is empty. Create the first record with “New record” or import a zone file.' }}</li>
        }
      </ul>

      <dialog #imp class="confirm wide" (click)="$event.target === imp ? imp.close() : null">
        <h3>Import a zone file</h3>
        <p class="soft">BIND format, one record per line. SOA and out-of-zone records are ignored.</p>
        <input type="file" accept=".zone,.txt,text/plain" (change)="pickFile($event)" aria-label="Zone file">
        <textarea [(ngModel)]="importText" name="it" rows="9" placeholder="www 300 IN A 10.0.0.5" aria-label="Zone file content" (ngModelChange)="importResult.set(null)"></textarea>
        <label class="check"><input type="checkbox" [(ngModel)]="importReplace" name="ir" (ngModelChange)="importResult.set(null)"> Replace the existing records</label>
        @if (importResult(); as r) {
          <div class="result">
            <b>{{ r.created }}</b> to create, <b>{{ r.skipped }}</b> already present
            @for (e of r.errors; track e) { <p class="error">{{ e }}</p> }
          </div>
        }
        <div class="actions">
          <button class="ghost" (click)="imp.close()">Close</button>
          <button class="ghost" (click)="runImport(true)" [disabled]="!importText.trim()">Preview</button>
          <button class="primary" (click)="confirmImport()" [disabled]="!importText.trim()">Import</button>
        </div>
      </dialog>
    } @else if (store.loaded()) {
      <div class="blank"><p class="big-hint">Zone not found</p><p class="soft">Pick another one from the list.</p></div>
    }`,
})
export class ZonePage {
  id = input.required<string>(); // from the :id route param
  private api = inject(Api);
  private ui = inject(Ui);
  store = inject(ZonesStore);
  private imp = viewChild<ElementRef<HTMLDialogElement>>('imp');

  empty = new Set<number>();
  zone = computed(() => this.store.zones().find(z => z.id === +this.id()));
  records = signal<Record[]>([]);
  filter = signal('');
  selected = signal(this.empty);

  importText = '';
  importReplace = false;
  importResult = signal<ZoneImportResult | null>(null);

  sortBy = signal<'' | 'type' | 'name' | 'value' | 'ttl'>('');
  desc = signal(false);

  shown = computed(() => {
    const f = this.filter().trim().toLowerCase();
    const list = f ? this.records().filter(r => `${r.name} ${r.type} ${r.value} ${r.note}`.toLowerCase().includes(f)) : this.records();
    const by = this.sortBy();
    if (!by) return list;
    const dir = this.desc() ? -1 : 1;
    const text = (a: string, b: string) => a.localeCompare(b, undefined, { numeric: true });
    const ip4 = (v: string) => /^\d+\.\d+\.\d+\.\d+$/.test(v) ? v.split('.').reduce((n, o) => n * 256 + +o, 0) : null;
    // reverse zone: the record name is only the tail of the address, so host sort uses the full IP
    const addr = (an: string, ai: string | null, bn: string, bi: string | null) => {
      const x = ai ? ip4(ai) : null, y = bi ? ip4(bi) : null;
      return x !== null && y !== null ? x - y : text(ai ?? an, bi ?? bn);
    };
    const cmp = (a: Record, b: Record) => {
      if (by === 'ttl') return (a.ttl ?? 0) - (b.ttl ?? 0);
      if (by === 'value') {
        const x = ip4(a.value), y = ip4(b.value);
        if (x !== null && y !== null) return x - y; // IPv4 by number, so .9 comes before .10
        if ((x === null) !== (y === null)) return x === null ? 1 : -1; // IPv4 first
        return text(a.value, b.value);
      }
      if (by === 'type') return text(a.type, b.type);
      return addr(a.name ?? '', this.ipOf(a), b.name ?? '', this.ipOf(b));
    };
    // ties fall back to type then name so the order is stable
    return [...list].sort((a, b) => dir * cmp(a, b) || text(a.type, b.type) || addr(a.name ?? '', this.ipOf(a), b.name ?? '', this.ipOf(b)));
  });
  allSelected = computed(() => this.shown().length > 0 && this.shown().every(r => this.selected().has(r.id)));

  constructor() {
    // Reload whenever the route param changes (zone -> zone keeps this component alive).
    effect(() => { this.id(); untracked(() => { this.filter.set(''); this.records.set([]); this.syncMsg.set(''); this.load(); }); });
  }

  async load() {
    await this.ui.run(async () => this.records.set(await this.api.invoke(recordsList, { zone: +this.id() })));
    // drop selections of records that no longer exist
    const ids = new Set(this.records().map(r => r.id));
    this.selected.update(s => new Set([...s].filter(i => ids.has(i))));
  }

  syncMsg = signal('');
  ipOf = (r: Record) => (r.type === 'PTR' && this.zone()?.reverse ? ptrToIp(this.zone()!.name, r.name ?? '') : null);
  syncPtr() {
    return this.ui.run(async () => {
      const r = await this.api.invoke(zonesSyncPtrCreate, { id: +this.id() });
      this.syncMsg.set(r.created ? `Created ${r.created} PTR${r.skipped ? `, ${r.skipped} already present` : ''}.` : 'No PTR to create: everything is in sync.');
      await this.load();
    });
  }

  onSaved(ptr: boolean) {
    this.load();
    if (ptr) this.store.load(); // a reverse zone may have been created
  }

  del(r: Record) {
    this.ui.ask(`Delete the record ${r.name}?`, `${r.type} ${r.value}`, () =>
      this.ui.run(async () => {
        await this.api.invoke(recordsDestroy, { id: r.id });
        await this.load();
      }));
  }

  // --- selection and bulk actions ---
  toggle(id: number) { this.selected.update(s => { const n = new Set(s); n.has(id) ? n.delete(id) : n.add(id); return n; }); }
  toggleAll() { this.selected.set(this.allSelected() ? new Set() : new Set(this.shown().map(r => r.id))); }
  toggleOne(r: Record) { return this.bulkOn([r.id], r.enabled === false ? 'enable' : 'disable'); }
  bulk(action: ActionEnum) { return this.bulkOn([...this.selected()], action); }
  private bulkOn(ids: number[], action: ActionEnum) {
    return this.ui.run(async () => { await this.api.invoke(recordsBulkCreate, { body: { ids, action } }); await this.load(); });
  }
  bulkDelete() {
    const n = this.selected().size;
    this.ui.ask(`Delete ${n} records?`, 'This cannot be undone.', () => { this.bulk('delete'); this.selected.set(new Set()); });
  }

  // --- zone file import / export ---
  async exportZone() {
    await this.ui.run(async () => {
      const text = await this.api.invoke(zonesExportRetrieve, { id: +this.id() });
      const a = document.createElement('a');
      a.href = URL.createObjectURL(new Blob([text], { type: 'text/plain' }));
      a.download = `${this.zone()!.name}.zone`;
      a.click();
      URL.revokeObjectURL(a.href);
    });
  }
  openImport() { this.importText = ''; this.importReplace = false; this.importResult.set(null); this.imp()!.nativeElement.showModal(); }
  async pickFile(e: Event) {
    const f = (e.target as HTMLInputElement).files?.[0];
    if (f) { this.importText = await f.text(); this.importResult.set(null); }
  }
  runImport(dry_run: boolean) {
    return this.ui.run(async () => {
      const r = await this.api.invoke(zonesImportCreate, { id: +this.id(), body: { text: this.importText, replace: this.importReplace, dry_run } });
      this.importResult.set(r);
      if (!dry_run) { await this.load(); if (!r.errors.length) this.imp()!.nativeElement.close(); }
    });
  }
  confirmImport() {
    if (!this.importReplace) { this.runImport(false); return; }
    this.ui.ask('Replace all records?', `The existing records of ${this.zone()?.name} will be deleted before the import.`, () => this.runImport(false));
  }
}
