import { Component, ElementRef, computed, inject, input, signal, viewChild } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Api } from '../api/api';
import { dhcpReservations6Create, dhcpReservations6Destroy, dhcpReservations6ExportRetrieve, dhcpReservations6ImportCreate, dhcpReservations6List, dhcpReservations6PartialUpdate } from '../api/functions';
import { Dhcp6Reservation, DhcpReservationImportResult } from '../api/models';
import { byIp } from '../lib/ip';
import { PingLive } from '../ping-live/ping-live';
import { Ping } from '../services/ping';
import { StepUp } from '../services/step-up';
import { Ui } from '../services/ui';

type Draft = { duid: string; ip: string; note: string };
const empty = (): Draft => ({ duid: '', ip: '', note: '' });

@Component({
  selector: 'app-dhcp-reservations6',
  imports: [FormsModule, PingLive],
  templateUrl: './dhcp-reservations6.html',
})
export class DhcpReservations6 {
  private api = inject(Api);
  private ui = inject(Ui);
  private stepUp = inject(StepUp);
  ping = inject(Ping);
  live = viewChild.required(PingLive);
  /** A DHCPv6 lease the user chose to make fixed: fills the form. */
  prefill = input<Partial<Draft> | null>(null);
  items = signal<Dhcp6Reservation[]>([]);
  filter = signal('');
  shown = computed(() => {
    const q = this.filter().trim().toLowerCase();
    const rows = q ? this.items().filter(r => `${r.duid} ${r.ip} ${r.mac} ${r.note ?? ''}`.toLowerCase().includes(q)) : this.items();
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
  load() { return this.ui.run(async () => this.items.set(await this.api.invoke(dhcpReservations6List))); }
  add() {
    return this.ui.run(async () => {
      await this.api.invoke(dhcpReservations6Create, { body: this.draft });
      this.draft = empty();
      await this.load();
    });
  }
  watch(r: Dhcp6Reservation) { this.live().open(r.ip); }
  pingOne(r: Dhcp6Reservation) { return this.ui.run(() => this.ping.once(r.ip)); }
  pingAll() { return this.ui.run(() => this.ping.run(this.items().filter(r => r.enabled !== false).map(r => r.ip))); }
  startEdit(r: Dhcp6Reservation) { this.edit = { duid: r.duid, ip: r.ip, note: r.note ?? '' }; this.editing.set(r.id); }
  save(r: Dhcp6Reservation) {
    return this.ui.run(async () => { await this.api.invoke(dhcpReservations6PartialUpdate, { id: r.id, body: this.edit }); this.editing.set(null); await this.load(); });
  }
  toggle(r: Dhcp6Reservation) {
    return this.ui.run(async () => { await this.api.invoke(dhcpReservations6PartialUpdate, { id: r.id, body: { enabled: r.enabled === false } }); await this.load(); });
  }
  del(r: Dhcp6Reservation) {
    this.ui.ask(`Delete the reservation ${r.ip}?`, 'The client gets an address from the pool at its next renewal.', () =>
      this.ui.run(async () => { await this.api.invoke(dhcpReservations6Destroy, { id: r.id }); await this.load(); }));
  }

  exportCsv() {
    return this.ui.run(async () => {
      const text = await this.api.invoke(dhcpReservations6ExportRetrieve);
      const a = document.createElement('a');
      a.href = URL.createObjectURL(new Blob([text], { type: 'text/csv' }));
      a.download = 'dhcp6-reservations.csv';
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
      const r = await this.api.invoke(dhcpReservations6ImportCreate, { body: { text: this.importText, replace: this.importReplace, dry_run }, 'X-MFA-Grant': grant || undefined });
      this.importResult.set(r);
      if (!dry_run) { await this.load(); if (!r.errors.length) this.imp().nativeElement.close(); }
    });
  }
  confirmImport() {
    if (!this.importReplace) { this.runImport(false); return; }
    this.ui.ask('Replace all reservations?', 'Every existing reservation is deleted before the import.', () => this.runImport(false));
  }
}
