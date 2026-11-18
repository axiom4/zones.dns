import { RouterLink, RouterLinkActive } from '@angular/router';
import { Component, DestroyRef, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Api } from '../api/api';
import { blockedImportedRetrieve, blockedListsList, blockedPublicPartialUpdate, blockedPublicRetrieve, blockedSourcesRetrieve, blockedSourcesSyncCreate, blockedSourcesUpdate } from '../api/functions';
import { BlocklistSource, BlocklistSources, PublicList } from '../api/models';
import { fieldErrors } from '../lib/error-text';
import { Ui } from '../services/ui';

@Component({
  selector: 'app-blocked-lists-page',
  imports: [FormsModule, RouterLink, RouterLinkActive],
  templateUrl: './blocked-lists-page.html',
})
export class BlockedListsPage {
  private api = inject(Api);
  private ui = inject(Ui);
  q = '';
  list = signal('');
  names = signal<string[]>([]);
  count = signal(0);
  lists = signal<PublicList[]>([]);

  loaded = signal(false);
  active = signal(true); // master switch: off = the imported domains are kept but ignored

  src = signal<BlocklistSources | null>(null); // the configured lists and what the last sync did
  errs = signal<Record<string, string>>({});
  newName = '';
  newUrl = '';
  private poll?: ReturnType<typeof setInterval>;

  constructor() {
    this.search();
    this.ui.run(async () => {
      const [pub, lst, src] = await Promise.all([this.api.invoke(blockedPublicRetrieve), this.api.invoke(blockedListsList), this.api.invoke(blockedSourcesRetrieve)]);
      this.active.set(pub.enabled);
      this.lists.set(lst);
      this.setSrc(src);
    });
    inject(DestroyRef).onDestroy(() => clearInterval(this.poll));
  }

  /** Keeps the lists; while a sync runs, asks every 3 s until it ends, then reloads the page's counts and says how it went. */
  private setSrc(s: BlocklistSources) {
    const was = this.src()?.running;
    this.src.set(s);
    if (s.running && !this.poll) {
      this.poll = setInterval(() => this.ui.run(async () => this.setSrc(await this.api.invoke(blockedSourcesRetrieve)), { silent: true }), 3000);
    } else if (!s.running && this.poll) {
      clearInterval(this.poll);
      this.poll = undefined;
    }
    if (was && !s.running) this.synced(s);
  }
  private synced(s: BlocklistSources) {
    return this.ui.run(async () => {
      this.lists.set(await this.api.invoke(blockedListsList));
      await this.search();
      if (s.error) throw new Error(`Sync stopped: ${s.error}. The old domains are kept.`);
      const bad = s.lists.filter(l => l.error).length, n = s.lists.length;
      this.ui.toast(bad ? `Synced ${n - bad} of ${n} lists; ${bad} could not be downloaded and kept their old domains` : `Synced ${n} ${n === 1 ? 'list' : 'lists'}`);
    });
  }
  private text(lists: BlocklistSource[]) { return lists.map(l => `${l.name}=${l.url}\n`).join(''); }
  private save(text: string) {
    return this.api.invoke(blockedSourcesUpdate, { body: { text } }).then(s => this.setSrc(s));
  }

  addList() {
    const name = this.newName.trim(), url = this.newUrl.trim(), before = this.src()?.text ?? '';
    return this.ui.run(async () => {
      this.errs.set({});
      try { await this.save(before + `${name}=${url}\n`); } catch (e) { this.errs.set(fieldErrors(e)); throw e; }
      this.newName = this.newUrl = '';
      this.ui.toast(`Added ${name}: choose Sync now to download it`);
    });
  }
  remove(l: BlocklistSource) {
    const s = this.src();
    if (!s) return;
    return this.ui.run(async () => {
      await this.save(this.text(s.lists.filter(x => x.name !== l.name)));
      this.ui.toast(`Removed ${l.name}: its domains go at the next sync`, () => this.save(s.text));
    });
  }
  sync() {
    return this.ui.run(async () => this.setSrc(await this.api.invoke(blockedSourcesSyncCreate)));
  }

  /** "https://host/…/file.txt": the full address is the title. */
  shortUrl(u: string) {
    try {
      const x = new URL(u), parts = x.pathname.split('/').filter(Boolean);
      return x.host + (parts.length > 1 ? '/…/' : '/') + (parts.at(-1) ?? '');
    } catch { return u; }
  }
  /** "5 minutes ago", "yesterday". */
  ago(iso: string) {
    const s = (Date.parse(iso) - Date.now()) / 1000, rtf = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' });
    for (const [unit, size] of [['day', 86400], ['hour', 3600], ['minute', 60]] as const) {
      if (Math.abs(s) >= size) return rtf.format(Math.round(s / size), unit);
    }
    return rtf.format(0, 'minute');
  }
  full(iso: string) { return new Date(iso).toLocaleString(); }
  switchAll() {
    return this.ui.run(async () => {
      this.active.set((await this.api.invoke(blockedPublicPartialUpdate, { body: { enabled: !this.active() } })).enabled);
      this.ui.toast(this.active() ? 'Public lists are on' : 'Public lists are off: none of their domains is blocked');
    });
  }
  pickList(name: string) {
    this.list.set(this.list() === name ? '' : name);
    return this.search();
  }

  search() { return this.fetch(0); }
  more() { return this.fetch(this.names().length); }
  private fetch(offset: number) {
    return this.ui.run(async () => {
      const r = await this.api.invoke(blockedImportedRetrieve, { q: this.q, list: this.list() || undefined, offset, limit: 100 });
      this.names.set(offset ? [...this.names(), ...r.names] : r.names);
      this.count.set(r.count);
      this.loaded.set(true);
    });
  }
}
