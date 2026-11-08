import { Component, ElementRef, computed, effect, inject, input, signal, untracked, viewChild } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Api } from '../api/api';
import { recordsBulkCreate, recordsDestroy, recordsList, zonesExportRetrieve, zonesImportCreate, zonesSyncPtrCreate } from '../api/functions';
import { ActionEnum, Record, ZoneImportResult } from '../api/models';
import { RecordForm } from '../record-form/record-form';
import { ptrToIp } from '../lib/reverse';
import { Ui } from '../services/ui';
import { ZonesStore } from '../services/zones-store';

@Component({
  selector: 'app-zone-page',
  imports: [FormsModule, RecordForm],
  templateUrl: './zone-page.html',
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
    const by = this.sortBy() || (this.zone()?.reverse ? 'name' : 'value'); // default: by IP
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
