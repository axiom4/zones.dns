import { Component, ElementRef, computed, effect, inject, input, signal, untracked, viewChild } from '@angular/core';
import { Title } from '@angular/platform-browser';
import { FormsModule } from '@angular/forms';
import { Api } from '../api/api';
import { recordsBulkCreate, recordsCreate, recordsDestroy, recordsList, zonesExportRetrieve, zonesImportCreate, zonesPartialUpdate, zonesSyncPtrCreate } from '../api/functions';
import { ActionEnum, Record, Zone, ZoneImportResult } from '../api/models';
import { RecordForm } from '../record-form/record-form';
import { ptrToIp } from '../lib/reverse';
import { StepUp } from '../services/step-up';
import { Ui, saveFile } from '../services/ui';
import { ZonesStore } from '../services/zones-store';

const PAGE = 100;

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
  off = computed(() => this.zone()?.enabled === false); // zone switched off: its records show as disabled and cannot be changed
  private stepUp = inject(StepUp);
  records = signal<Record[]>([]);
  loading = signal(true); // no "this zone is empty" flash before the first answer
  importBusy = signal(false);
  filter = signal('');
  selected = signal(this.empty);

  importText = '';
  importReplace = false;
  importResult = signal<ZoneImportResult | null>(null);

  sortBy = signal<'' | 'type' | 'name' | 'value' | 'ttl'>('');
  desc = signal(false);

  // the server searches, sorts and cuts the pages (GET /api/records/): this is the page on screen
  readonly PAGE = PAGE;
  shown = computed(() => this.records());
  total = signal(0); // records of the zone, whatever the search
  count = signal(0); // records that match the search: the pages are cut from these
  page = signal(0);
  private timer?: ReturnType<typeof setTimeout>;
  allSelected = computed(() => this.shown().length > 0 && this.shown().every(r => this.selected().has(r.id)));

  constructor() {
    // Reload whenever the route param changes (zone -> zone keeps this component alive).
    effect(() => { this.id(); untracked(() => { this.filter.set(''); this.records.set([]); this.total.set(0); this.loading.set(true); }); });
    // a new zone, search or order starts again from the first page (the search waits for a pause in the typing)
    let first = true;
    effect(() => {
      this.id(); this.filter(); this.sortBy(); this.desc();
      untracked(() => {
        clearTimeout(this.timer);
        this.selected.set(this.empty);
        this.page.set(0);
        this.timer = setTimeout(() => this.load(), first ? 0 : 250);
        first = false;
      });
    });
    // the tab title names the zone (the route only knows "Zone"; a title strategy may add the app name after it)
    const title = inject(Title);
    effect(() => { const n = this.zone()?.name; if (n) setTimeout(() => title.setTitle(title.getTitle().replace(/^[^–]*?(?=\s–|$)/, n))); });
  }

  /** "www (A)": how a record is named in labels, toasts and questions */
  label = (r: Record) => `${r.name || '@'} (${r.type})`;

  async load(): Promise<void> {
    const f = this.filter().trim();
    let again = false;
    await this.ui.run(async () => {
      const r = await this.api.invoke(recordsList, { zone: +this.id(), q: f || undefined, sort: this.sortBy() || undefined, desc: this.desc() || undefined, limit: PAGE, offset: this.page() * PAGE });
      if (!r.results.length && this.page() > 0) { // the last record of the last page went: back to the page before
        this.page.set(Math.ceil(r.count / PAGE) - 1);
        again = true;
        return;
      }
      this.records.set(r.results);
      this.count.set(r.count);
      if (!f) this.total.set(r.count);
    });
    if (again) return this.load();
    this.loading.set(false);
  }

  go(delta: number) {
    this.page.update(p => p + delta);
    this.selected.set(this.empty); // a selection is of the page on screen
    return this.load();
  }

  toggleZone(z: Zone) {
    this.selected.set(this.empty);
    return this.ui.run(async () => {
      const off = z.enabled !== false; // switching a zone off stops serving it: confirmed with a second factor, like deleting it
      const grant = off ? await this.stepUp.request(`zone-delete:${z.id}`, `Turn off zone ${z.name}`, 'Turn off zone') : '';
      if (grant === null) return;
      await this.api.invoke(zonesPartialUpdate, { id: z.id, body: { enabled: !off }, 'X-MFA-Grant': grant || undefined });
      await this.store.load();
      this.ui.toast(off ? `Turned off zone ${z.name}: it is no longer served` : `Zone ${z.name} is served again`);
    });
  }

  ipOf = (r: Record) => (r.type === 'PTR' && this.zone()?.reverse ? ptrToIp(this.zone()!.name, r.name ?? '') : null);
  syncPtr() {
    return this.ui.run(async () => {
      const r = await this.api.invoke(zonesSyncPtrCreate, { id: +this.id() });
      await this.load();
      this.ui.toast(r.created ? `Created ${r.created} PTR ${r.created === 1 ? 'record' : 'records'}${r.skipped ? ` (${r.skipped} already present)` : ''}` : 'No PTR record to create: everything is in sync');
    });
  }

  onSaved(ptr: boolean) {
    this.load();
    if (ptr) this.store.load(); // a reverse zone may have been created
  }

  /** No question first: the toast offers Undo, which creates the record again. */
  del(r: Record) {
    return this.ui.run(async () => {
      await this.api.invoke(recordsDestroy, { id: r.id });
      this.selected.update(s => { const n = new Set(s); n.delete(r.id); return n; });
      await this.load();
      this.ui.toast(`Deleted ${this.label(r)}`, () => this.restore([r]));
    });
  }
  private async restore(rs: Record[]) {
    for (const r of rs) {
      await this.api.invoke(recordsCreate, { body: { zone: r.zone, name: r.name, type: r.type, value: r.value, ttl: r.ttl, enabled: r.enabled, note: r.note } });
    }
    await this.load();
    this.ui.toast(rs.length === 1 ? `Restored ${this.label(rs[0])}` : `Restored ${rs.length} records`);
  }

  // --- selection and bulk actions ---
  toggle(id: number) { this.selected.update(s => { const n = new Set(s); n.has(id) ? n.delete(id) : n.add(id); return n; }); }
  toggleAll() { this.selected.set(this.allSelected() ? new Set() : new Set(this.shown().map(r => r.id))); }
  toggleOne(r: Record) { return this.bulkOn([r.id], r.enabled === false ? 'enable' : 'disable'); }
  bulk(action: ActionEnum) { return this.bulkOn([...this.selected()], action); }
  private bulkOn(ids: number[], action: ActionEnum) {
    return this.ui.run(async () => {
      // deleting or switching off all the records of the zone, or most of them (10 or more and over half), is confirmed with a second
      // factor, like deleting the zone. The same rule as the server (views/record.py, BULK_MIN).
      const total = this.total();
      const all = (action === 'delete' || action === 'disable') && (ids.length >= total || (ids.length >= 10 && ids.length * 2 > total));
      const n = ids.length, what = n === 1 ? this.label(this.records().find(r => r.id === ids[0])!) : `${n} records`;
      const verb = action === 'delete' ? 'Delete' : 'Turn off';
      const grant = all ? await this.stepUp.request(`zone-delete:${this.id()}`, `${verb} ${what} in ${this.zone()?.name}`, `${verb} ${n === 1 ? 'record' : 'records'}`) : ''; // '' = nothing to prove, null = cancelled
      if (grant === null) return;
      const gone = action === 'delete' ? this.records().filter(r => ids.includes(r.id)) : [];
      await this.api.invoke(recordsBulkCreate, { body: { ids, action }, 'X-MFA-Grant': grant || undefined });
      if (action === 'delete') this.selected.set(new Set());
      await this.load();
      if (action === 'delete') this.ui.toast(`Deleted ${what}`, () => this.restore(gone));
      else if (n > 1) this.ui.toast(`${action === 'enable' ? 'Turned on' : 'Turned off'} ${what}`);
    });
  }
  bulkDelete() {
    const n = this.selected().size;
    this.ui.ask(`Delete ${n} ${n === 1 ? 'record' : 'records'}?`, 'You can undo it right after, from the notice.', () => { this.bulk('delete'); }, n === 1 ? 'Delete record' : `Delete ${n} records`);
  }

  // --- zone file import / export ---
  async exportZone() {
    await this.ui.run(async () => {
      saveFile(await this.api.invoke(zonesExportRetrieve, { id: +this.id() }), `${this.zone()!.name}.zone`, 'text/plain');
    });
  }
  openImport() { this.importText = ''; this.importReplace = false; this.importResult.set(null); this.imp()!.nativeElement.showModal(); }
  async pickFile(e: Event) {
    const f = (e.target as HTMLInputElement).files?.[0];
    if (f) { this.importText = await f.text(); this.importResult.set(null); }
  }
  async runImport(dry_run: boolean) {
    this.importBusy.set(true);
    await this.ui.run(async () => {
      const name = this.zone()?.name;
      const grant = this.importReplace && !dry_run ? await this.stepUp.request(`zone-delete:${this.id()}`, `Replace all records of ${name}`, 'Replace records') : ''; // replacing deletes every record first
      if (grant === null) return;
      const r = await this.api.invoke(zonesImportCreate, { id: +this.id(), body: { text: this.importText, replace: this.importReplace, dry_run }, 'X-MFA-Grant': grant || undefined });
      this.importResult.set(r);
      if (!dry_run) {
        await this.load();
        if (!r.errors.length) { this.imp()!.nativeElement.close(); this.ui.toast(`Imported ${r.created} ${r.created === 1 ? 'record' : 'records'} into ${name}`); }
      }
    });
    this.importBusy.set(false);
  }
  confirmImport() {
    if (!this.importReplace) { this.runImport(false); return; }
    this.ui.ask('Replace all records?', `The existing records of ${this.zone()?.name} are deleted before the import. This cannot be undone.`, () => this.runImport(false), 'Replace records');
  }
}
