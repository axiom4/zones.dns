import { Component, OnDestroy, computed, inject, signal } from '@angular/core';
import { DecimalPipe } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { Api } from '../api/api';
import { geoDestinationsRetrieve } from '../api/functions';
import { Destinations } from '../api/models';
import { GeoMap } from '../geo-map/geo-map';
import { countryName, flag } from '../lib/geo-util';
import { Period } from '../services/period';
import { Ui } from '../services/ui';

@Component({
  selector: 'app-geo-page',
  imports: [FormsModule, RouterLink, GeoMap, DecimalPipe],
  templateUrl: './geo-page.html',
})
export class GeoPage implements OnDestroy {
  private api = inject(Api);
  private ui = inject(Ui);
  flag = flag; name = countryName;
  hours = 24;
  data = signal<Destinations | null>(null);
  failed = signal(false);
  filter = signal('');
  /** The countries matching the search: name, code, or one of their most requested domains. */
  shown = computed(() => {
    const cs = this.data()?.countries ?? [], f = this.filter().trim().toLowerCase();
    return f ? cs.filter(c => c.country.toLowerCase() === f || countryName(c.country).toLowerCase().includes(f) || c.top_domains.some(n => n.includes(f))) : cs;
  });
  private opened = signal(new Set<string>());
  private timer?: ReturnType<typeof setTimeout>;
  private retries = 0;

  private router = inject(Router);
  private periodStore = inject(Period);
  constructor() {
    const h = Number(inject(ActivatedRoute).snapshot.queryParamMap.get('hours')); // ?hours=168: a reload or a shared link keeps the period
    this.hours = [1, 24, 168, 720].includes(h) ? h : this.periodStore.pick([1, 24, 168, 720]); // else the period last chosen anywhere
    this.load();
  }
  changed() {
    this.periodStore.remember(this.hours);
    this.router.navigate([], { queryParams: { hours: this.hours !== 24 ? this.hours : null }, replaceUrl: true });
    this.load();
  }
  private destroyed = false;
  ngOnDestroy() { this.destroyed = true; clearTimeout(this.timer); }

  async load(auto = false) {
    clearTimeout(this.timer);
    if (!auto) this.retries = 0;
    await this.ui.run(async () => {
      try { this.data.set(await this.api.invoke(geoDestinationsRetrieve, { hours: this.hours })); this.failed.set(false); }
      catch (e) { this.failed.set(true); throw e; }
    }, { silent: auto });
    // Unknown addresses are looked up in batches: ask again a few times until they are all located.
    if (!this.destroyed && (this.data()?.pending ?? 0) > 0 && this.retries++ < 8) this.timer = setTimeout(() => this.load(true), 2500);
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
  /** Share of the queries answered with an address, one decimal under 10%. */
  share(q: number) { const t = this.data()?.scanned; if (!t) return 0; const p = (q / t) * 100; return p < 10 ? Math.round(p * 10) / 10 : Math.round(p); }
  pct(q: number, d: Destinations) { return Math.round((q / Math.max(...d.countries.map(c => c.queries), 1)) * 100); }
}
