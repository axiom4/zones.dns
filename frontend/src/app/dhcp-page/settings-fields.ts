import { Component, input } from '@angular/core';
import { FormsModule } from '@angular/forms';

/** One setting: label in plain words, the technical term in brackets, a one-line help. */
export interface SettingField {
  key: string; label: string; term?: string; help: string;
  kind?: 'check' | 'number' | 'textarea'; ph?: string; min?: number; max?: number; wide?: boolean;
}

/** The inputs of a settings section: a visible label, the help tied with aria-describedby, the server's error next to its field. */
@Component({
  selector: 'app-settings-fields',
  imports: [FormsModule],
  template: `
<div class="sf-grid">
  @for (f of fields(); track f.key) {
    @let e = errs()[f.key];
    @if (f.kind === 'check') {
      <div class="sf sf-check" [class.wide]="f.wide">
        <input type="checkbox" [id]="id(f)" [ngModel]="model()[f.key]" (ngModelChange)="model()[f.key] = $event" [ngModelOptions]="{ standalone: true }"
               [attr.aria-describedby]="desc(f)" [attr.aria-invalid]="e ? true : null">
        <label class="lbl" [for]="id(f)">{{ f.label }}@if (f.term) {<span class="term">{{ ' (' + f.term + ')' }}</span>}</label>
        <small class="help" [id]="id(f) + '-h'">{{ f.help }}</small>
        @if (e) { <small class="bad" [id]="id(f) + '-e'">{{ e }}</small> }
      </div>
    } @else {
      <div class="sf" [class.wide]="f.wide || f.kind === 'textarea'">
        <label class="lbl" [for]="id(f)">{{ f.label }}@if (f.term) {<span class="term">{{ ' (' + f.term + ')' }}</span>}</label>
        @if (f.kind === 'textarea') {
          <textarea [id]="id(f)" rows="4" spellcheck="false" [placeholder]="f.ph ?? ''" [ngModel]="model()[f.key]" (ngModelChange)="model()[f.key] = $event"
                    [ngModelOptions]="{ standalone: true }" [attr.aria-describedby]="desc(f)" [attr.aria-invalid]="e ? true : null"></textarea>
        } @else {
          <input [id]="id(f)" [type]="f.kind === 'number' ? 'number' : 'text'" [attr.min]="f.min ?? null" [attr.max]="f.max ?? null" autocomplete="off"
                 [placeholder]="f.ph ?? ''" [ngModel]="model()[f.key]" (ngModelChange)="model()[f.key] = $event" [ngModelOptions]="{ standalone: true }"
                 [attr.aria-describedby]="desc(f)" [attr.aria-invalid]="e ? true : null">
        }
        <small class="help" [id]="id(f) + '-h'">{{ f.help }}</small>
        @if (e) { <small class="bad" [id]="id(f) + '-e'">{{ e }}</small> }
      </div>
    }
  }
</div>`,
})
export class SettingsFields {
  fields = input.required<SettingField[]>();
  model = input.required<Record<string, any>>();
  errs = input<Record<string, string>>({});
  prefix = input('sf');

  id(f: SettingField) { return `${this.prefix()}-${f.key}`; }
  desc(f: SettingField) { return this.errs()[f.key] ? `${this.id(f)}-h ${this.id(f)}-e` : `${this.id(f)}-h`; }
}

/** The settings that differ between the saved copy and the edited one (to know if a dialog has changes, and which risky switches moved). */
export function changed<T extends object>(saved: T, now: T): (keyof T)[] {
  return (Object.keys({ ...saved, ...now }) as (keyof T)[]).filter(k => JSON.stringify(norm(saved[k])) !== JSON.stringify(norm(now[k])));
}
const norm = (v: unknown) => (v === '' || v === undefined ? null : v); // a cleared field is the same as one never set
