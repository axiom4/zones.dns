import { Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Api } from '../api/api';
import { blockedImportedRetrieve, blockedListsList, blockedPublicPartialUpdate, blockedPublicRetrieve } from '../api/functions';
import { PublicList } from '../api/models';
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
  list = ''; // show only the domains of this list ('' = all)
  lists = signal<PublicList[]>([]);
  names = signal<string[]>([]);
  count = signal(0);

  active = signal(true); // master switch: off = the imported domains are kept but ignored

  constructor() {
    this.search();
    this.ui.run(async () => { this.active.set((await this.api.invoke(blockedPublicRetrieve)).enabled); this.lists.set(await this.api.invoke(blockedListsList, {})); });
  }
  switchAll() {
    return this.ui.run(async () => { this.active.set((await this.api.invoke(blockedPublicPartialUpdate, { body: { enabled: !this.active() } })).enabled); });
  }

  pick(name: string) { this.list = this.list === name ? '' : name; return this.search(); }

  search() { return this.fetch(0); }
  more() { return this.fetch(this.names().length); }
  private fetch(offset: number) {
    return this.ui.run(async () => {
      const r = await this.api.invoke(blockedImportedRetrieve, { q: this.q, list: this.list || undefined, offset, limit: 100 });
      this.names.set(offset ? [...this.names(), ...r.names] : r.names);
      this.count.set(r.count);
    });
  }
}
