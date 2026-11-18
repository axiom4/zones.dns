import { Injectable, computed, inject, signal } from '@angular/core';
import { Router } from '@angular/router';
import { Api } from '../api/api';
import { zonesCreate, zonesDestroy, zonesList, zonesReverseCreate } from '../api/functions';
import { Zone } from '../api/models';
import { StepUp } from './step-up';
import { Ui } from './ui';

@Injectable({ providedIn: 'root' })
export class ZonesStore {
  private api = inject(Api);
  private ui = inject(Ui);
  private router = inject(Router);
  private stepUp = inject(StepUp);

  zones = signal<Zone[]>([]);
  loaded = signal(false);
  defaultZone = signal(''); // name from DEFAULT_ZONE (server setting)
  groups = computed(() => [
    { title: 'Your zones', zones: this.zones().filter(z => !z.reverse) },
    { title: 'Reverse zones', zones: this.zones().filter(z => z.reverse) },
  ]);

  load() { return this.ui.run(async () => { this.zones.set(await this.api.invoke(zonesList)); this.loaded.set(true); }); }

  async add(name: string) {
    let ok = false;
    await this.ui.run(async () => {
      const z = await this.api.invoke(zonesCreate, { body: { name } });
      await this.load();
      ok = true;
      await this.router.navigate(['/zones', z.id]); // before the toast: a navigation clears notices
      this.ui.toast(`Created zone ${z.name}`);
    });
    return ok;
  }

  async addReverse(cidr: string) {
    let ok = false;
    await this.ui.run(async () => {
      const z = await this.api.invoke(zonesReverseCreate, { body: { cidr } });
      await this.load();
      ok = true;
      await this.router.navigate(['/zones', z.id]); // before the toast: a navigation clears notices
      this.ui.toast(`Created reverse zone ${z.name}`);
    });
    return ok;
  }

  del(z: Zone) {
    this.ui.ask(`Delete zone ${z.name}?`, 'All its records are deleted too. This cannot be undone.', () =>
      this.ui.run(async () => {
        const grant = await this.stepUp.request(`zone-delete:${z.id}`, `Delete zone ${z.name}`, 'Delete zone'); // '' = no second factor set up, null = cancelled
        if (grant === null) return;
        await this.api.invoke(zonesDestroy, { id: z.id, 'X-MFA-Grant': grant || undefined });
        await this.load();
        if (this.router.url === `/zones/${z.id}`) { // straight to where the index would send us: a second navigation would clear the toast
          const home = this.zones().find(x => x.name === this.defaultZone());
          await this.router.navigate(home ? ['/zones', home.id] : ['/zones']);
        }
        this.ui.toast(`Deleted zone ${z.name}`);
      }), 'Delete zone');
  }
}
