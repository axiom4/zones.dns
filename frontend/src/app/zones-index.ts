import { Component, effect, inject } from '@angular/core';
import { Router } from '@angular/router';
import { ZonesStore } from './zones-store';

@Component({
  selector: 'app-zones-index',
  template: `<div class="blank">
    <p class="big-hint">Choose a zone</p>
    <p class="soft">Pick it from the list of zones to view and edit its records.</p>
  </div>`,
})
export class ZonesIndex {
  constructor() {
    const store = inject(ZonesStore), router = inject(Router);
    // DEFAULT_ZONE (server setting): open that zone when no zone is chosen. Unknown name = stay on the hint.
    effect(() => {
      const z = store.loaded() && store.defaultZone() ? store.zones().find(x => x.name === store.defaultZone()) : undefined;
      if (z) router.navigate(['/zones', z.id], { replaceUrl: true });
    });
  }
}
