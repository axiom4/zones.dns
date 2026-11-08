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
      this.router.navigate(['/zones', z.id]);
    });
    return ok;
  }

  async addReverse(cidr: string) {
    let ok = false;
    await this.ui.run(async () => {
      const z = await this.api.invoke(zonesReverseCreate, { body: { cidr } });
      await this.load();
      ok = true;
      this.router.navigate(['/zones', z.id]);
    });
    return ok;
  }

  del(z: Zone) {
    this.ui.ask(`Delete ${z.name}?`, 'All its records will be deleted too. This cannot be undone. You will be asked for your second factor.', () =>
      this.ui.run(async () => {
        const grant = await this.stepUp.request(`zone-delete:${z.id}`); // '' = no second factor set up, null = cancelled
        if (grant === null) return;
        await this.api.invoke(zonesDestroy, { id: z.id, 'X-MFA-Grant': grant || undefined });
        if (this.router.url === `/zones/${z.id}`) this.router.navigate(['/zones']);
        await this.load();
      }));
  }
}
