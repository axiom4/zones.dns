import { Component, OnDestroy, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { Api } from '../api/api';
import { geoDestinationsRetrieve } from '../api/functions';
import { Destinations } from '../api/models';
import { GeoMap } from '../geo-map/geo-map';
import { countryName, flag } from '../lib/geo-util';
import { Ui } from '../services/ui';

@Component({
  selector: 'app-geo-page',
  imports: [FormsModule, RouterLink, GeoMap],
  templateUrl: './geo-page.html',
})
export class GeoPage implements OnDestroy {
  private api = inject(Api);
  private ui = inject(Ui);
  flag = flag; name = countryName;
  hours = 24;
  data = signal<Destinations | null>(null);
  private opened = signal(new Set<string>());
  private timer?: ReturnType<typeof setTimeout>;
  private retries = 0;

  constructor() { this.load(); }
  ngOnDestroy() { clearTimeout(this.timer); }

  async load(auto = false) {
    clearTimeout(this.timer);
    if (!auto) this.retries = 0;
    await this.ui.run(async () => this.data.set(await this.api.invoke(geoDestinationsRetrieve, { hours: this.hours })));
    // Unknown addresses are looked up in batches: ask again a few times until they are all located.
    if ((this.data()?.pending ?? 0) > 0 && this.retries++ < 8) this.timer = setTimeout(() => this.load(true), 2500);
  }

  date(iso: string) { return new Date(iso).toLocaleDateString(); }

  /** A country was clicked on the map: open it in the list and bring it into view. */
  focus(code: string) {
    this.opened.update(s => new Set(s).add(code));
    setTimeout(() => document.getElementById('c-' + code)?.scrollIntoView({ behavior: 'smooth', block: 'center' }));
  }

  isOpen(code: string) { return this.opened().has(code); }
  toggle(code: string) { this.opened.update(s => { const n = new Set(s); n.has(code) ? n.delete(code) : n.add(code); return n; }); }

  abroad() { return (this.data()?.countries ?? []).filter(c => c.country !== 'PRIV' && c.country !== '??').length; }
  externalShare() {
    const cs = this.data()?.countries ?? [];
    const total = cs.reduce((a, c) => a + c.queries, 0);
    return total ? Math.round((cs.filter(c => c.country !== 'PRIV').reduce((a, c) => a + c.queries, 0) / total) * 100) : 0;
  }
  pct(q: number, d: Destinations) { return Math.round((q / Math.max(...d.countries.map(c => c.queries), 1)) * 100); }
}
