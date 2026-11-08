import { Component, ElementRef, computed, inject, input, output, signal, viewChild } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Api } from '../api/api';
import { recordsCreate, recordsUpdate } from '../api/functions';
import { Record, RecordRequest, TypeEnum } from '../api/models';
import { GROUPS, SPEC, TTL_PRESETS, TXT_TEMPLATES, TypeSpec, compose, defaults, parse, validate } from '../lib/record-types';
import { ptrToIp } from '../lib/reverse';
import { Ui } from '../services/ui';

/** Guided create/edit dialog for one DNS record. Open it with open() (new) or open(record) (edit). */
@Component({
  selector: 'app-record-form',
  imports: [FormsModule],
  templateUrl: './record-form.html',
})
export class RecordForm {
  zoneId = input.required<number>();
  zoneName = input.required<string>();
  reverse = input(false); // reverse zone: PTR is the natural type and names are address parts
  records = input.required<Record[]>(); // for autocomplete
  saved = output<boolean>(); // true if a PTR was requested (reverse zone may be new)

  private api = inject(Api);
  ui = inject(Ui);
  private dlg = viewChild.required<ElementRef<HTMLDialogElement>>('dlg');

  groups = GROUPS;
  ttlPresets = TTL_PRESETS;
  txtTemplates = TXT_TEMPLATES;
  Number = Number;
  parse_ = (v: string) => !!parse(this.spec(), v);

  type = signal<TypeEnum>('A');
  spec = computed<TypeSpec>(() => SPEC[this.type()]);
  editingId = signal<number | null>(null);
  raw = signal(false);
  submitted = signal(false);

  name = '@'; ttl: number | string = 300; note = ''; enabled = true; createPtr = false; rawText = '';
  vals: { [k: string]: string } = defaults(SPEC['A']);

  ip = () => (this.reverse() ? ptrToIp(this.zoneName(), this.name.trim()) : null);
  fqdn = () => { const n = this.name.trim() || '@'; return n === '@' ? this.zoneName() : `${n}.${this.zoneName()}`; };
  nameOptions = computed(() => [...new Set(['@', '*', 'www', 'mail', 'ns1', ...this.records().map(r => r.name!)])]);
  hostOptions = computed(() => [...new Set(this.records().filter(r => r.name !== '*').map(r => (r.name === '@' ? this.zoneName() : `${r.name}.${this.zoneName()}`) + '.'))]);

  open(r?: Record) {
    this.ui.error.set('');
    this.submitted.set(false);
    if (r) {
      this.editingId.set(r.id);
      this.type.set(r.type);
      const p = parse(SPEC[r.type], r.value);
      this.vals = p ?? defaults(SPEC[r.type]);
      this.raw.set(!p);
      this.rawText = r.value;
      this.name = r.name ?? '@'; this.ttl = r.ttl ?? 300; this.note = r.note ?? ''; this.enabled = r.enabled !== false; this.createPtr = false;
    } else {
      this.editingId.set(null);
      this.pickType(this.reverse() ? 'PTR' : 'A');
      this.name = this.reverse() ? '' : '@'; this.ttl = 300; this.note = ''; this.enabled = true; this.createPtr = false;
    }
    this.dlg().nativeElement.showModal();
  }

  pickType(t: TypeEnum) { this.type.set(t); this.vals = defaults(SPEC[t]); this.raw.set(false); this.rawText = ''; }
  toRaw() { this.rawText = compose(this.spec(), this.vals); this.raw.set(true); }
  fromRaw() { const p = parse(this.spec(), this.rawText); if (p) { this.vals = p; this.raw.set(false); } }

  rdata() { return this.raw() ? this.rawText.trim() : compose(this.spec(), this.vals); }
  previewLine() { return `${this.name.trim() || '@'} ${this.ttl} IN ${this.type()} ${this.rdata()}`; }
  error(f: { key: string } & Parameters<typeof validate>[0]) { return this.submitted() ? validate(f, this.vals[f.key]) : ''; }

  private valid() {
    if (!this.name.trim() || !(Number.isInteger(+this.ttl) && +this.ttl >= 0)) return false;
    return this.raw() ? !!this.rawText.trim() : this.spec().fields.every(f => !validate(f, this.vals[f.key]));
  }

  async save(again: boolean) {
    this.submitted.set(true);
    if (!this.valid()) return;
    const ptr = this.createPtr;
    const body: RecordRequest = {
      zone: this.zoneId(), name: this.name.trim(), type: this.type(), value: this.rdata(),
      ttl: +this.ttl, enabled: this.enabled, note: this.note, create_ptr: ptr,
    };
    const id = this.editingId();
    await this.ui.run(async () => {
      if (id === null) await this.api.invoke(recordsCreate, { body });
      else await this.api.invoke(recordsUpdate, { id, body });
    });
    if (this.ui.error()) return; // stay open and show the server's message
    this.saved.emit(ptr);
    if (again) {
      this.vals = defaults(this.spec()); this.rawText = ''; this.raw.set(false); this.name = ''; this.note = ''; this.submitted.set(false);
      this.createPtr = ptr;
    } else this.dlg().nativeElement.close();
  }
}
