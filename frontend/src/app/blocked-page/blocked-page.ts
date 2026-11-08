import { Component, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Api } from '../api/api';
import { blockedCreate, blockedDestroy, blockedList, blockedPartialUpdate } from '../api/functions';
import { BlockedDomain } from '../api/models';
import { Ui } from '../services/ui';

@Component({
  selector: 'app-blocked-page',
  imports: [FormsModule],
  templateUrl: './blocked-page.html',
})
export class BlockedPage {
  private api = inject(Api);
  private ui = inject(Ui);
  blocked = signal<BlockedDomain[]>([]);
  filter = signal('');
  shown = computed(() => { const q = this.filter().trim().toLowerCase(); return q ? this.blocked().filter(b => b.name.includes(q)) : this.blocked(); });
  name = '';
  editing = signal<number | null>(null);
  draft = '';

  constructor() { this.load(); }

  load() { return this.ui.run(async () => this.blocked.set(await this.api.invoke(blockedList))); }
  edit(b: BlockedDomain) { this.draft = b.name; this.editing.set(b.id); }
  save(b: BlockedDomain) {
    return this.ui.run(async () => { await this.api.invoke(blockedPartialUpdate, { id: b.id, body: { name: this.draft } }); this.editing.set(null); await this.load(); });
  }
  add() {
    return this.ui.run(async () => { await this.api.invoke(blockedCreate, { body: { name: this.name } }); this.name = ''; await this.load(); });
  }
  toggle(b: BlockedDomain) {
    return this.ui.run(async () => { await this.api.invoke(blockedPartialUpdate, { id: b.id, body: { enabled: b.enabled === false } }); await this.load(); });
  }
  del(b: BlockedDomain) {
    this.ui.ask(`Unblock ${b.name}?`, 'The domain and its subdomains will resolve again.', () =>
      this.ui.run(async () => { await this.api.invoke(blockedDestroy, { id: b.id }); await this.load(); }));
  }
}
