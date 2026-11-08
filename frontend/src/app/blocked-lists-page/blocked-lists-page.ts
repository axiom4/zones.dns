import { Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Api } from '../api/api';
import { blockedImportedRetrieve, blockedPublicPartialUpdate, blockedPublicRetrieve } from '../api/functions';
import { Ui } from '../services/ui';

@Component({
  selector: 'app-blocked-lists-page',
  imports: [FormsModule],
  templateUrl: './blocked-lists-page.html',
})
export class BlockedListsPage {
  private api = inject(Api);
  private ui = inject(Ui);
  q = '';
  names = signal<string[]>([]);
  count = signal(0);

  active = signal(true); // master switch: off = the imported domains are kept but ignored

  constructor() {
    this.search();
    this.ui.run(async () => this.active.set((await this.api.invoke(blockedPublicRetrieve)).enabled));
  }
  switchAll() {
    return this.ui.run(async () => { this.active.set((await this.api.invoke(blockedPublicPartialUpdate, { body: { enabled: !this.active() } })).enabled); });
  }

  search() { return this.fetch(0); }
  more() { return this.fetch(this.names().length); }
  private fetch(offset: number) {
    return this.ui.run(async () => {
      const r = await this.api.invoke(blockedImportedRetrieve, { q: this.q, offset, limit: 100 });
      this.names.set(offset ? [...this.names(), ...r.names] : r.names);
      this.count.set(r.count);
    });
  }
}
