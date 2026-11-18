import { Component, effect, inject } from '@angular/core';
import { Router, RouterLink } from '@angular/router';
import { Shell } from '../shell/shell';
import { ZonesStore } from '../services/zones-store';

@Component({
  selector: 'app-zones-index',
  imports: [RouterLink],
  templateUrl: './zones-index.html',
})
export class ZonesIndex {
  store = inject(ZonesStore);
  shell = inject(Shell, { optional: true }); // the New zone dialogs live in the shell, the parent of this page
  constructor() {
    const store = this.store, router = inject(Router);
    // DEFAULT_ZONE (server setting): open that zone when no zone is chosen. Unknown name = stay on the list.
    effect(() => {
      const z = store.loaded() && store.defaultZone() ? store.zones().find(x => x.name === store.defaultZone()) : undefined;
      if (z) router.navigate(['/zones', z.id], { replaceUrl: true });
    });
  }
}
