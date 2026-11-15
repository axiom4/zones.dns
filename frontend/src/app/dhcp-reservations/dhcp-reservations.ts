import { Component, ElementRef, computed, inject, input, signal, viewChild } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Api } from '../api/api';
import { dhcpReservationsCreate, dhcpReservationsDestroy, dhcpReservationsExportRetrieve, dhcpReservationsImportCreate, dhcpReservationsList, dhcpReservationsPartialUpdate } from '../api/functions';
import { DhcpReservation, DhcpReservationImportResult } from '../api/models';
import { byIp } from '../lib/ip';
import { StepUp } from '../services/step-up';
import { Ui } from '../services/ui';

type Draft = { mac: string; ip: string; hostname: string; note: string };
const empty = (): Draft => ({ mac: '', ip: '', hostname: '', note: '' });

@Component({
  selector: 'app-dhcp-reservations',
  imports: [FormsModule],
  templateUrl: './dhcp-reservations.html',
})
export class DhcpReservations {
  private api = inject(Api);
  private ui = inject(Ui);
  private stepUp = inject(StepUp);
  /** A lease the user chose to make fixed: fills the form. */
  prefill = input<Partial<Draft> | null>(null);
  items = signal<DhcpReservation[]>([]);
  filter = signal('');
  shown = computed(() => {
    const q = this.filter().trim().toLowerCase();
    const rows = q ? this.items().filter(r => `${r.mac} ${r.ip} ${r.hostname ?? ''} ${r.note ?? ''}`.toLowerCase().includes(q)) : this.items();
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

  ngOnInit() { const p = this.prefill(); if (p) this.draft = { ...empty(), ...p }; }
  load() { return this.ui.run(async () => this.items.set(await this.api.invoke(dhcpReservationsList))); }
  add() {
    return this.ui.run(async () => {
      await this.api.invoke(dhcpReservationsCreate, { body: this.draft });
      this.draft = empty();
      await this.load();
    });
  }
  startEdit(r: DhcpReservation) { this.edit = { mac: r.mac, ip: r.ip, hostname: r.hostname ?? '', note: r.note ?? '' }; this.editing.set(r.id); }
  save(r: DhcpReservation) {
    return this.ui.run(async () => { await this.api.invoke(dhcpReservationsPartialUpdate, { id: r.id, body: this.edit }); this.editing.set(null); await this.load(); });
  }
  toggle(r: DhcpReservation) {
    return this.ui.run(async () => { await this.api.invoke(dhcpReservationsPartialUpdate, { id: r.id, body: { enabled: r.enabled === false } }); await this.load(); });
  }
  del(r: DhcpReservation) {
    this.ui.ask(`Delete the reservation ${r.mac} → ${r.ip}?`, 'The client gets an address from the pool at its next renewal.', () =>
      this.ui.run(async () => { await this.api.invoke(dhcpReservationsDestroy, { id: r.id }); await this.load(); }));
  }

  exportCsv() {
    return this.ui.run(async () => {
      const text = await this.api.invoke(dhcpReservationsExportRetrieve);
      const a = document.createElement('a');
      a.href = URL.createObjectURL(new Blob([text], { type: 'text/csv' }));
      a.download = 'dhcp-reservations.csv';
      a.click();
      URL.revokeObjectURL(a.href);
    });
  }
  openImport() { this.importText = ''; this.importReplace = false; this.importResult.set(null); this.imp().nativeElement.showModal(); }
  async pickFile(e: Event) {
    const f = (e.target as HTMLInputElement).files?.[0];
    if (f) { this.importText = await f.text(); this.importResult.set(null); }
  }
  runImport(dry_run: boolean) {
    return this.ui.run(async () => {
      const grant = this.importReplace && !dry_run ? await this.stepUp.request('dhcp-replace') : ''; // replacing deletes every reservation first
      if (grant === null) return;
      const r = await this.api.invoke(dhcpReservationsImportCreate, { body: { text: this.importText, replace: this.importReplace, dry_run }, 'X-MFA-Grant': grant || undefined });
      this.importResult.set(r);
      if (!dry_run) { await this.load(); if (!r.errors.length) this.imp().nativeElement.close(); }
    });
  }
  confirmImport() {
    if (!this.importReplace) { this.runImport(false); return; }
    this.ui.ask('Replace all reservations?', 'Every existing reservation is deleted before the import.', () => this.runImport(false));
  }
}
