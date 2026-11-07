import { Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Api } from './api/api';
import { blockedImportedRetrieve } from './api/functions';
import { Ui } from './ui';

@Component({
  selector: 'app-blocked-lists-page',
  imports: [FormsModule],
  template: `
    <header>
      <div>
        <h2>Public lists</h2>
        <p class="soft">{{ count() }} domains {{ q ? 'found' : 'imported' }}. Read-only: updated by <code>import_blocklist</code>; to remove one, use the Django admin.</p>
      </div>
    </header>
    <form class="composer" (ngSubmit)="search()">
      <input class="grow" name="q" [(ngModel)]="q" placeholder="search the imported lists" autocomplete="off" aria-label="Search the imported lists">
      <button class="primary">Search</button>
    </form>
    <ul class="records">
      @for (n of names(); track n) {
        <li><span class="rvalue">{{ n }}</span></li>
      } @empty {
        <li class="empty">{{ q ? 'No results.' : 'No list imported. Run import_blocklist.' }}</li>
      }
      @if (names().length < count()) {
        <li><button (click)="more()">Show more</button></li>
      }
    </ul>`,
})
export class BlockedListsPage {
  private api = inject(Api);
  private ui = inject(Ui);
  q = '';
  names = signal<string[]>([]);
  count = signal(0);

  constructor() { this.search(); }

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
