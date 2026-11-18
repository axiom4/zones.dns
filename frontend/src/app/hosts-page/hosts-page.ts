import { Component, ElementRef, Injector, afterNextRender, computed, inject, signal, viewChild } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Api } from '../api/api';
import { hostsCreate, hostsDestroy, hostsList, hostsPartialUpdate } from '../api/functions';
import { StaticHost } from '../api/models';
import { fieldErrors } from '../lib/error-text';
import { Ui } from '../services/ui';

type Errs = { [k: string]: string };
const FIELDS = ['name', 'address', 'ttl', 'note'];

@Component({
  selector: 'app-hosts-page',
  imports: [FormsModule],
  templateUrl: './hosts-page.html',
})
export class HostsPage {
  private api = inject(Api);
  private ui = inject(Ui);
  private injector = inject(Injector);
  private addName = viewChild<ElementRef<HTMLInputElement>>('addName');
  hosts = signal<StaticHost[]>([]);
  loaded = signal(false);
  busy = signal(false);
  addErr = signal<Errs>({});
  editErr = signal<Errs>({});
  filter = signal('');
  shown = computed(() => { const q = this.filter().trim().toLowerCase(); return q ? this.hosts().filter(h => (h.name + ' ' + h.address + ' ' + (h.note ?? '')).toLowerCase().includes(q)) : this.hosts(); });
  draft = { name: '', address: '', ttl: null as number | null, note: '' };
  editing = signal<number | null>(null);
  edit = { name: '', address: '', ttl: 300 as number | null, note: '' };

  constructor() { this.load(); }

  async load() { await this.ui.run(async () => this.hosts.set(await this.api.invoke(hostsList))); this.loaded.set(true); }

  /** Runs a save: messages about a field go next to it (set), anything else to the shell's notice. true = it worked. */
  private async submit(f: () => Promise<unknown>, set: (e: Errs) => void): Promise<boolean> {
    if (this.busy()) return false;
    this.busy.set(true); set({});
    try { await f(); return true; } catch (e) {
      const fe = fieldErrors(e), mine = FIELDS.filter(k => fe[k]);
      set(fe);
      if (!mine.length || mine.length < Object.keys(fe).length) await this.ui.run(() => Promise.reject(e));
      this.focus('[aria-invalid=true]');
      return false;
    } finally { this.busy.set(false); }
  }
  private focus(sel: string) { afterNextRender(() => document.querySelector<HTMLElement>(sel)?.focus(), { injector: this.injector }); }

  async add() {
    const { ttl, ...rest } = this.draft;
    if (await this.submit(() => this.api.invoke(hostsCreate, { body: { ...rest, ...(ttl != null ? { ttl } : {}) } }), e => this.addErr.set(e))) {
      this.ui.toast(`Added ${rest.name} (${rest.address})`);
      this.draft = { name: '', address: '', ttl: null, note: '' };
      this.addName()?.nativeElement.focus(); // ready for the next one
      await this.load();
    }
  }
  startEdit(h: StaticHost) {
    this.edit = { name: h.name, address: h.address, ttl: h.ttl ?? 300, note: h.note ?? '' };
    this.editErr.set({});
    this.editing.set(h.id);
    this.focus('#he-name');
  }
  cancelEdit(h: StaticHost) { this.editing.set(null); this.focus(`[data-edit="${h.id}"]`); }
  async save(h: StaticHost) {
    if (await this.submit(() => this.api.invoke(hostsPartialUpdate, { id: h.id, body: { ...this.edit, ttl: this.edit.ttl ?? 300 } }), e => this.editErr.set(e))) {
      this.editing.set(null);
      this.ui.toast(`Saved ${this.edit.name}`);
      await this.load();
      this.focus(`[data-edit="${h.id}"]`);
    }
  }
  toggle(h: StaticHost) {
    return this.ui.run(async () => { await this.api.invoke(hostsPartialUpdate, { id: h.id, body: { enabled: h.enabled === false } }); await this.load(); });
  }
  /** No question first: the toast offers Undo, which adds the host again. */
  del(h: StaticHost) {
    return this.ui.run(async () => {
      await this.api.invoke(hostsDestroy, { id: h.id });
      await this.load();
      this.ui.toast(`Deleted ${h.name} (${h.address})`, async () => {
        await this.api.invoke(hostsCreate, { body: { name: h.name, address: h.address, ttl: h.ttl, note: h.note, enabled: h.enabled } });
        await this.load();
        this.ui.toast(`Restored ${h.name}`);
      });
    });
  }
}
