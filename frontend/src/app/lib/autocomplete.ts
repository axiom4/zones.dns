import { Component, computed, input, model, output, signal } from '@angular/core';

export interface AcOption { value: string; label?: string }

let next = 0;

/** Text box with a list of suggestions: filters while typing (value or label contains the text), arrows + Enter + Escape, click to pick. Free text stays allowed. */
@Component({
  selector: 'app-autocomplete',
  template: `
    <input type="text" role="combobox" autocomplete="off" aria-autocomplete="list"
      [placeholder]="placeholder()" [attr.aria-label]="label()" [attr.aria-expanded]="open() && shown().length > 0"
      [attr.aria-controls]="id" [attr.aria-activedescendant]="active() >= 0 ? id + '-' + active() : null"
      [value]="value()" (input)="type($any($event.target).value)" (focus)="show()" (click)="show()" (keydown)="key($event)" (blur)="open.set(false)">
    @if (open() && shown().length) {
      <ul class="ac" role="listbox" [id]="id">
        @for (o of shown(); track o.value; let i = $index) {
          <li role="option" [id]="id + '-' + i" [class.on]="i === active()" [attr.aria-selected]="i === active()"
              (pointerdown)="$event.preventDefault(); pick(o)" (pointerenter)="active.set(i)">
            <span class="v">{{ o.value }}</span>@if (o.label) { <span class="l">{{ o.label }}</span> }
          </li>
        }
      </ul>
    }`,
  styles: `
    :host { position: relative; display: inline-block; width: 190px; }
    input { width: 100%; }
    .ac { position: absolute; z-index: 20; top: calc(100% + 4px); left: 0; min-width: 100%; width: max-content; max-width: min(24rem, 90vw); max-height: 16rem; overflow: auto;
          margin: 0; padding: .3rem; list-style: none; background: var(--surface); border: 1.5px solid var(--line); border-radius: 12px; box-shadow: var(--shadow); }
    li { display: flex; justify-content: space-between; gap: 1rem; padding: .4rem .6rem; border-radius: 8px; cursor: pointer; font-size: 13px; }
    li.on { background: var(--brand-soft); }
    .v { font-family: var(--mono); }
    @media (max-width: 1100px) {
      .ac { width: 100%; max-width: none; }  /* as wide as the box: a list that starts in the right half would run off the screen */
      li { flex-wrap: wrap; gap: .1rem .6rem; padding-block: .6rem; }
    }
    .l { color: var(--muted); }`,
})
export class Autocomplete {
  value = model('');
  options = input<AcOption[]>([]);
  placeholder = input('');
  label = input('');
  opened = output<void>(); // the list was opened: the parent can refresh the options

  id = `ac-${next++}`;
  open = signal(false);
  active = signal(-1);
  shown = computed(() => {
    const q = this.value().trim().toLowerCase();
    return this.options().filter(o => !q || o.value.toLowerCase().includes(q) || o.label?.toLowerCase().includes(q)).slice(0, 50); // shortcut: first 50 matches, no scrolling load
  });

  show() { if (!this.open()) { this.open.set(true); this.opened.emit(); } }
  type(v: string) { this.value.set(v); this.active.set(-1); this.open.set(true); }
  pick(o: AcOption) { this.value.set(o.value); this.open.set(false); this.active.set(-1); }

  key(e: KeyboardEvent) {
    const n = this.shown().length;
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault();
      this.show();
      if (n) this.active.update(i => (e.key === 'ArrowDown' ? i + 1 : i - 1 + (i < 0 ? n + 1 : 0) + n) % n);
    } else if (e.key === 'Enter' && this.open() && this.active() >= 0) {
      e.preventDefault();
      this.pick(this.shown()[this.active()]);
    } else if (e.key === 'Escape' && this.open()) {
      e.preventDefault();
      this.open.set(false);
    }
  }
}
