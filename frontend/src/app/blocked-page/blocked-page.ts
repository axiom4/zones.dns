import { RouterLink, RouterLinkActive } from '@angular/router';
import { Component, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Api } from '../api/api';
import { blockedCreate, blockedDestroy, blockedList, blockedPartialUpdate, blockedSuggestionsList, blockedPersonalPartialUpdate, blockedPersonalRetrieve } from '../api/functions';
import { BlockedDomain, Count } from '../api/models';
import { Ui } from '../services/ui';
import { fieldErrors } from '../lib/error-text';
import { focusSoon } from '../ping-live/focus';

@Component({
  selector: 'app-blocked-page',
  imports: [FormsModule, RouterLink, RouterLinkActive],
  templateUrl: './blocked-page.html',
})
export class BlockedPage {
  private api = inject(Api);
  private ui = inject(Ui);
  blocked = signal<BlockedDomain[]>([]);
  loaded = signal(false);
  errs = signal<Record<string, string>>({});
  filter = signal('');
  shown = computed(() => { const q = this.filter().trim().toLowerCase(); return q ? this.blocked().filter(b => b.name.includes(q)) : this.blocked(); });
  name = '';
  regex = false;
  hours = 0; // an allow that lasts this many hours; 0 = always
  editing = signal<number | null>(null);
  draft = '';

  suggestions = signal<Count[]>([]);
  active = signal(true); // master switch: off = the blocks below are kept but ignored

  constructor() { this.load(); }

  load() {
    return this.ui.run(async () => {
      this.blocked.set(await this.api.invoke(blockedList));
      this.active.set((await this.api.invoke(blockedPersonalRetrieve)).enabled);
      this.suggestions.set(await this.api.invoke(blockedSuggestionsList, {}));
      this.loaded.set(true);
    });
  }
  switchAll() {
    this.editing.set(null); // an edit in progress is dropped when the feature goes off
    return this.ui.run(async () => {
      this.active.set((await this.api.invoke(blockedPersonalPartialUpdate, { body: { enabled: !this.active() } })).enabled);
      this.ui.toast(this.active() ? 'Personal blocks are on' : 'Personal blocks are off: nothing in this list is blocked or allowed');
    });
  }
  edit(b: BlockedDomain) { this.draft = b.name; this.editing.set(b.id); }
  cancelEdit(b: BlockedDomain) { this.editing.set(null); focusSoon(`bl-edit-${b.id}`); }
  save(b: BlockedDomain) {
    return this.ui.run(async () => {
      await this.api.invoke(blockedPartialUpdate, { id: b.id, body: { name: this.draft } });
      this.editing.set(null);
      await this.load();
      focusSoon(`bl-edit-${b.id}`);
    }, { ok: `Saved ${this.draft}` });
  }
  add(allow = false) {
    const name = this.name.trim(), hours = allow ? this.hours : 0;
    const how = allow ? `Allowed ${name}${hours ? ` for ${hours === 1 ? '1 hour' : hours === 24 ? '1 day' : '7 days'}` : ''}` : `Blocked ${name}`;
    return this.ui.run(async () => {
      this.errs.set({});
      const expires = hours ? new Date(Date.now() + hours * 3_600_000).toISOString() : null;
      let made: BlockedDomain;
      try { made = await this.api.invoke(blockedCreate, { body: { name, allow, regex: this.regex, expires } }); } catch (e) { this.errs.set(fieldErrors(e)); throw e; }
      this.name = '';
      await this.load();
      this.ui.toast(how, async () => { await this.api.invoke(blockedDestroy, { id: made.id }); await this.load(); });
    });
  }
  expired(b: BlockedDomain) { return !!b.expires && new Date(b.expires).getTime() < Date.now(); }
  until(b: BlockedDomain) { return new Date(b.expires!).toLocaleString([], { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' }); }
  suggested(name: string) {
    return this.ui.run(async () => {
      const made = await this.api.invoke(blockedCreate, { body: { name } });
      await this.load();
      this.ui.toast(`Blocked ${name}`, async () => { await this.api.invoke(blockedDestroy, { id: made.id }); await this.load(); });
    });
  }
  toggle(b: BlockedDomain) {
    const on = b.enabled === false;
    return this.ui.run(async () => { await this.api.invoke(blockedPartialUpdate, { id: b.id, body: { enabled: on } }); await this.load(); },
      { ok: `${on ? 'Turned on' : 'Turned off'} the ${b.allow ? 'exception' : 'block'} for ${b.name}` });
  }
  /** Deleted at once, with Undo in the notice: it makes the same entry again. */
  del(b: BlockedDomain) {
    return this.ui.run(async () => {
      await this.api.invoke(blockedDestroy, { id: b.id });
      await this.load();
      focusSoon('bl-name');
      this.ui.toast(b.allow ? `Removed the exception for ${b.name}` : `Unblocked ${b.name}`, async () => {
        await this.api.invoke(blockedCreate, { body: { name: b.name, allow: b.allow, regex: b.regex, expires: b.expires, enabled: b.enabled } });
        await this.load();
      });
    });
  }
}
