import { Component, ElementRef, computed, inject, input, output, signal, viewChild } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Api } from './api/api';
import { recordsCreate, recordsUpdate } from './api/functions';
import { Record, RecordRequest, TypeEnum } from './api/models';
import { GROUPS, SPEC, TTL_PRESETS, TXT_TEMPLATES, TypeSpec, compose, defaults, parse, validate } from './record-types';
import { ptrToIp } from './reverse';
import { Ui } from './ui';

/** Guided create/edit dialog for one DNS record. Open it with open() (new) or open(record) (edit). */
@Component({
  selector: 'app-record-form',
  imports: [FormsModule],
  template: `
    <dialog #dlg class="confirm form-dialog" (click)="$event.target === dlg ? dlg.close() : null">
      <form (ngSubmit)="save(false)" novalidate>
        <h3>{{ editingId() === null ? 'New record' : 'Edit record' }} <span class="soft">in {{ zoneName() }}</span></h3>

        <fieldset>
          <legend>{{ editingId() === null ? 'What do you want to create?' : 'Record type' }}</legend>
          <div class="typepick">
            @for (g of groups; track g.name) {
              <div class="tgroup">
                <span class="tglabel">{{ g.name }}</span>
                <div class="tgrid">
                  @for (s of g.specs; track s.type) {
                    <button type="button" class="tchip" [class.on]="type() === s.type" (click)="pickType(s.type)" [attr.aria-pressed]="type() === s.type">
                      <b>{{ s.type }}</b><span>{{ s.title }}</span>
                    </button>
                  }
                </div>
              </div>
            }
          </div>
        </fieldset>

        <div class="about">
          <p>{{ spec().about }}</p>
          <p class="soft">Example: <code>{{ spec().example }}</code></p>
        </div>

        <label class="field">
          <span class="lbl">Name</span>
          <input name="name" list="fnames" autocomplete="off" [(ngModel)]="name" placeholder="www" aria-describedby="h-name">
          <small id="h-name" class="help">
            @if (reverse()) {
              The last part of the IP address: for <code>10.0.0.7</code> in a /24 enter <code>7</code>.
            } @else {
              The part to the left of the zone. <code>www</code> becomes <code>www.{{ zoneName() }}</code>;
              <code>&#64;</code> is the zone itself; <code>*</code> answers every subdomain that has no record of its own.
            }
          </small>
          @if (submitted() && !name.trim()) { <small class="bad">Required field.</small> }
          <small class="full">Full name: <b>{{ fqdn() }}</b>@if (ip(); as a) { · address <b>{{ a }}</b> }</small>
        </label>

        @if (!raw()) {
          @for (f of spec().fields; track f.key) {
            <label class="field">
              <span class="lbl">{{ f.label }}@if (f.optional) { <em> · optional</em> }</span>
              @switch (f.kind) {
                @case ('select') {
                  <select [name]="f.key" [(ngModel)]="vals[f.key]" [attr.aria-describedby]="'h-' + f.key">
                    @for (o of f.options; track o.value) { <option [value]="o.value">{{ o.label }}</option> }
                  </select>
                }
                @case ('textarea') {
                  <textarea [name]="f.key" rows="3" [(ngModel)]="vals[f.key]" [placeholder]="f.placeholder ?? ''" [attr.aria-describedby]="'h-' + f.key"></textarea>
                }
                @default {
                  <input [name]="f.key" [type]="f.kind === 'number' ? 'number' : 'text'" autocomplete="off"
                         [attr.list]="f.key === 'target' || f.key === 'replacement' ? 'fhosts' : null"
                         [min]="f.min ?? null" [max]="f.max ?? null"
                         [(ngModel)]="vals[f.key]" [placeholder]="f.placeholder ?? ''" [attr.aria-describedby]="'h-' + f.key">
                }
              }
              <small [id]="'h-' + f.key" class="help">{{ f.help }}</small>
              @if (error(f); as e) { <small class="bad">{{ e }}</small> }
            </label>
          }
          @if (type() === 'TXT') {
            <div class="presets">Templates:
              @for (t of txtTemplates; track t.label) { <button type="button" class="mini" (click)="vals['text'] = t.text">{{ t.label }}</button> }
            </div>
          }
          <button type="button" class="link small" (click)="toRaw()">Edit as text (advanced)</button>
        } @else {
          <label class="field">
            <span class="lbl">Value (text)</span>
            <textarea name="raw" rows="3" [(ngModel)]="rawText" aria-describedby="h-raw"></textarea>
            <small id="h-raw" class="help">BIND zone file format. The guided fields do not recognise this value, so it is edited as text.</small>
            @if (submitted() && !rawText.trim()) { <small class="bad">Required field.</small> }
          </label>
          @if (parse_(rawText)) { <button type="button" class="link small" (click)="fromRaw()">Back to the guided fields</button> }
        }

        <label class="field">
          <span class="lbl">TTL (seconds)</span>
          <input name="ttl" type="number" min="0" [(ngModel)]="ttl" aria-describedby="h-ttl">
          <span class="presets">
            @for (p of ttlPresets; track p.value) { <button type="button" class="mini" [class.on]="+ttl === p.value" (click)="ttl = p.value">{{ p.label }}</button> }
          </span>
          <small id="h-ttl" class="help">How long clients may reuse the answer without asking again. Low = changes show up quickly; high = less traffic.</small>
          @if (submitted() && !(Number.isInteger(+ttl) && +ttl >= 0)) { <small class="bad">Enter a whole number greater than or equal to 0.</small> }
        </label>

        <label class="field">
          <span class="lbl">Note <em>· optional</em></span>
          <input name="note" [(ngModel)]="note" autocomplete="off" placeholder="What is this record for?" aria-describedby="h-note">
          <small id="h-note" class="help">Only for you: it is never sent in DNS answers.</small>
        </label>

        <div class="opts">
          <label class="check"><input type="checkbox" name="enabled" [(ngModel)]="enabled"> Enabled
            <small class="help">when disabled it stays saved but DNS does not serve it</small></label>
          @if (editingId() === null && (type() === 'A' || type() === 'AAAA')) {
            <label class="check"><input type="checkbox" name="ptr" [(ngModel)]="createPtr"> Also create the reverse record (PTR)
              <small class="help">lets you go from the address back to the name</small></label>
          }
        </div>

        <div class="preview"><span class="soft">Will be saved as</span><code>{{ previewLine() }}</code></div>

        @if (ui.error()) { <p class="error" role="alert">{{ ui.error() }}</p> }

        <div class="actions">
          <button type="button" class="ghost" (click)="dlg.close()">Cancel</button>
          @if (editingId() === null) { <button type="button" class="ghost" (click)="save(true)">Save and new</button> }
          <button class="primary">Save</button>
        </div>

        <datalist id="fnames">@for (n of nameOptions(); track n) { <option [value]="n"></option> }</datalist>
        <datalist id="fhosts">@for (h of hostOptions(); track h) { <option [value]="h"></option> }</datalist>
      </form>
    </dialog>`,
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
