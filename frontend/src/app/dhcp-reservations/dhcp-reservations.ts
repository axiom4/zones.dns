import { Component, ElementRef, computed, inject, input, signal, viewChild } from '@angular/core';
import { KeyValuePipe } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Api } from '../api/api';
import { dhcpVendorRetrieve, dhcpReservationsCreate, dhcpReservationsDestroy, dhcpReservationsExportRetrieve, dhcpReservationsImportCreate, dhcpReservationsList, dhcpReservationsPartialUpdate } from '../api/functions';
import { DhcpReservation, DhcpReservationImportResult } from '../api/models';
import { byIp } from '../lib/ip';
import { fieldErrors } from '../lib/error-text';
import { pingSummary } from '../ping-live/ping-summary';
import { focusSoon } from '../ping-live/focus';
import { PingLive } from '../ping-live/ping-live';
import { Ping } from '../services/ping';
import { StepUp } from '../services/step-up';
import { Ui, saveFile } from '../services/ui';

type Draft = { mac: string; ip: string; hostname: string; note: string };
const empty = (): Draft => ({ mac: '', ip: '', hostname: '', note: '' });

@Component({
  selector: 'app-dhcp-reservations',
  imports: [FormsModule, KeyValuePipe, PingLive],
  templateUrl: './dhcp-reservations.html',
})
export class DhcpReservations {
  private api = inject(Api);
  private ui = inject(Ui);
  private stepUp = inject(StepUp);
  ping = inject(Ping);
  live = viewChild.required(PingLive);
  vendorHint = signal('');
  items = signal<DhcpReservation[]>([]);
  loaded = signal(false);
  /** The device filter of the DHCP page (one search box for every tab). */
  filter = input('');
  errs = signal<Record<string, string>>({});
  editErrs = signal<Record<string, string>>({});
  shown = computed(() => {
    const q = this.filter().trim().toLowerCase();
    const rows = q ? this.items().filter(r => `${r.mac} ${r.ip} ${r.hostname ?? ''} ${r.note ?? ''} ${r.vendor ?? ''}`.toLowerCase().includes(q)) : this.items();
    return [...rows].sort((a, b) => byIp(a.ip, b.ip));
  });
  draft = empty();
  editing = signal<number | null>(null);
  edit = empty();
  imp = viewChild.required<ElementRef<HTMLDialogElement>>('imp');
  importText = '';
  importReplace = false;
  importResult = signal<DhcpReservationImportResult | null>(null);

  constructor() { this.load(); }

  load() { return this.ui.run(async () => { this.items.set(await this.api.invoke(dhcpReservationsList)); this.loaded.set(true); }); }
  add() {
    const d = this.draft;
    return this.ui.run(async () => {
      this.errs.set({});
      try { await this.api.invoke(dhcpReservationsCreate, { body: d }); } catch (e) { this.errs.set(fieldErrors(e)); throw e; }
      this.draft = empty();
      this.vendorHint.set('');
      await this.load();
    }, { ok: `Reserved ${d.ip} for ${d.hostname || d.mac}` });
  }
  watch(r: DhcpReservation) { this.live().open(r.ip); }
  pingOne(r: DhcpReservation) { return this.ui.run(async () => { await this.ping.once(r.ip); this.ui.toast(`${r.ip}: ${this.ping.label(r.ip)}`); }); }
  pingAll() {
    const list = this.shown().filter(r => r.enabled !== false).map(r => r.ip);
    return this.ui.run(async () => { await this.ping.run(list); this.ui.toast(pingSummary(this.ping, list)); });
  }
  /** Who made the card, shown under the MAC field while the user fills in the form. */
  async lookupVendor() {
    const mac = this.draft.mac.trim();
    if (mac.replace(/[^0-9a-f]/gi, '').length !== 12) { this.vendorHint.set(''); return; }
    try {
      const v = await this.api.invoke(dhcpVendorRetrieve, { mac });
      if (mac === this.draft.mac.trim()) this.vendorHint.set(v.vendor ?? (v.private ? 'Private (random) address: no maker' : 'Unknown maker'));
    } catch { this.vendorHint.set(''); } // only a hint: the form still works
  }
  startEdit(r: DhcpReservation) {
    this.edit = { mac: r.mac, ip: r.ip, hostname: r.hostname ?? '', note: r.note ?? '' };
    this.editErrs.set({});
    this.editing.set(r.id);
    focusSoon(`rv4-em-${r.id}`);
  }
  cancelEdit(r: DhcpReservation) { this.editing.set(null); focusSoon(`rv4-edit-${r.id}`); }
  save(r: DhcpReservation) {
    return this.ui.run(async () => {
      this.editErrs.set({});
      try { await this.api.invoke(dhcpReservationsPartialUpdate, { id: r.id, body: this.edit }); } catch (e) { this.editErrs.set(fieldErrors(e)); throw e; }
      this.editing.set(null);
      await this.load();
      focusSoon(`rv4-edit-${r.id}`);
    }, { ok: `Saved the reservation of ${this.edit.ip}` });
  }
  toggle(r: DhcpReservation) {
    return this.ui.run(async () => { await this.api.invoke(dhcpReservationsPartialUpdate, { id: r.id, body: { enabled: r.enabled === false } }); await this.load(); },
      { ok: `${r.enabled === false ? 'Turned on' : 'Turned off'} the reservation of ${r.ip}` });
  }
  /** Deleted at once, with Undo in the notice: it creates the same reservation again. */
  del(r: DhcpReservation) {
    return this.ui.run(async () => {
      await this.api.invoke(dhcpReservationsDestroy, { id: r.id });
      await this.load();
      focusSoon('rv4-mac');
      this.ui.toast(`Deleted the reservation of ${r.ip}`, async () => {
        await this.api.invoke(dhcpReservationsCreate, { body: { mac: r.mac, ip: r.ip, hostname: r.hostname, note: r.note, enabled: r.enabled } });
        await this.load();
      });
    });
  }

  exportCsv() {
    return this.ui.run(async () => {
      saveFile(await this.api.invoke(dhcpReservationsExportRetrieve), 'dhcp-reservations.csv', 'text/csv');
    });
  }
  openImport() { this.importText = ''; this.importReplace = false; this.importResult.set(null); this.imp().nativeElement.showModal(); }
  async pickFile(e: Event) {
    const f = (e.target as HTMLInputElement).files?.[0];
    if (f) { this.importText = await f.text(); this.importResult.set(null); }
  }
  runImport(dry_run: boolean) {
    return this.ui.run(async () => {
      const grant = this.importReplace && !dry_run ? await this.stepUp.request('dhcp-replace', 'Replace all IPv4 reservations', 'Replace reservations') : ''; // replacing deletes every reservation first
      if (grant === null) return;
      const r = await this.api.invoke(dhcpReservationsImportCreate, { body: { text: this.importText, replace: this.importReplace, dry_run }, 'X-MFA-Grant': grant || undefined });
      this.importResult.set(r);
      if (!dry_run) {
        await this.load();
        if (!r.errors.length) { this.imp().nativeElement.close(); this.ui.toast(`Imported: ${r.created} added, ${r.updated} updated, ${r.skipped} unchanged`); }
      }
    });
  }
  confirmImport() {
    if (!this.importReplace) { this.runImport(false); return; }
    this.ui.ask('Replace all reservations?', 'Every existing IPv4 reservation is deleted before the import.', () => this.runImport(false), 'Replace reservations');
  }
}
