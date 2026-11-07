import { Component, OnDestroy, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { Api } from './api/api';
import { geoDestinationsRetrieve } from './api/functions';
import { Destinations } from './api/models';
import { GeoMap } from './geo-map';
import { countryName, flag } from './geo-util';
import { Ui } from './ui';

@Component({
  selector: 'app-geo-page',
  imports: [FormsModule, RouterLink, GeoMap],
  template: `
    <header>
      <div>
        <h2>Geolocation</h2>
        <p class="soft">Where the DNS answers point: country and network of the addresses clients will connect to.</p>
      </div>
      <div class="actions">
        <select [(ngModel)]="hours" name="h" (ngModelChange)="load()" aria-label="Period">
          <option [ngValue]="1">Last hour</option>
          <option [ngValue]="24">Last 24 hours</option>
          <option [ngValue]="168">Last 7 days</option>
          <option [ngValue]="720">Last 30 days</option>
        </select>
        <button class="ghost" (click)="load()">Refresh</button>
      </div>
    </header>

    @if (data(); as d) {
      @if (d.pending > 0) {
        <p class="about">Locating {{ d.pending }} more addresses: the page updates by itself.</p>
      }

      @if (d.geoip.city) {
        <p class="soft geosrc">Local GeoIP active: {{ d.geoip.city.type }} (updated {{ date(d.geoip.city.built) }}){{ d.geoip.asn ? ' · ' + d.geoip.asn.type : '' }}. Locations never leave this server.@if (d.geoip.city.file.includes('dbip')) { <span> Location data: <a href="https://db-ip.com" target="_blank" rel="noopener">IP Geolocation by DB-IP</a> (CC BY 4.0).</span> }</p>
      } @else {
        <p class="about">Country-level location, worked out through DNS. For <b>cities</b> on the map, set up a local GeoIP database in <code>backend/.env</code>:
          <code>GEOIP_CITY_DB=/path/GeoLite2-City.mmdb</code> (optionally <code>GEOIP_ASN_DB</code>) and restart the server.{{ d.geoip.configured_city ? ' The file you set cannot be read.' : '' }}</p>
      }

      <div class="tiles">
        <div class="tile"><b>{{ d.scanned }}</b><span>Answered queries</span></div>
        <div class="tile"><b>{{ d.ips_total }}</b><span>Destination addresses</span></div>
        <div class="tile"><b>{{ abroad() }}</b><span>External countries</span></div>
        <div class="tile"><b>{{ externalShare() }}%</b><span>Queries to the outside</span></div>
      </div>

      <section class="panel">
        <h3>Map</h3>
        <app-geo-map [countries]="d.countries" [points]="d.points" (pick)="focus($event)" />
        <p class="soft note">Countries are shaded by the queries pointing to them@if (d.points.length) {; circles are cities ({{ d.points.length }})}. Click a country for details.</p>
      </section>

      <section class="panel">
        <h3>By country</h3>
        @for (c of d.countries; track c.country) {
          <div class="country" [id]="'c-' + c.country" [class.open]="isOpen(c.country)">
            <button class="crow" (click)="toggle(c.country)" [attr.aria-expanded]="isOpen(c.country)">
              <span class="flag" aria-hidden="true">{{ flag(c.country) }}</span>
              <span class="cname">{{ name(c.country) }}@if (c.country.length === 2 && c.country !== '??') {<span class="soft"> {{ c.country }}</span>}</span>
              <span class="cbar"><i [style.width.%]="pct(c.queries, d)"></i></span>
              <span class="cnum"><b>{{ c.queries }}</b> queries</span>
              <span class="cnum soft">{{ c.ips }} addresses · {{ c.domains }} domains</span>
              <span class="chev2" aria-hidden="true">▸</span>
            </button>
            @if (isOpen(c.country)) {
              <div class="cdetail">
                @if (c.cities.length) {
                  <p class="soft">Cities</p>
                  <div class="chips">@for (n of c.cities; track n) { <span class="chip-a">{{ n }}</span> }</div>
                }
                <p class="soft">Most requested domains</p>
                <div class="chips">@for (n of c.top_domains; track n) { <a class="chip-a link" routerLink="/audit" [queryParams]="{ domain: n }" title="Analyse the domain">{{ n }}</a> }</div>
                @if (c.asns.length) {
                  <p class="soft">Networks</p>
                  <div class="chips">@for (a of c.asns; track a) { <span class="chip-a">{{ a }}</span> }</div>
                }
              </div>
            }
          </div>
        } @empty {
          <p class="soft">No answers with addresses in the chosen period. Answers appear as clients make queries.</p>
        }
        <p class="soft note">The country is where the network is registered: for services with several sites (CDN, anycast) it may differ from the server's physical location.</p>
      </section>

      @if (d.networks.length) {
        <section class="panel">
          <h3>Most contacted networks</h3>
          <table class="anstable">
            <thead><tr><th>Network</th><th>Name</th><th>Country</th><th>Queries</th><th>Addresses</th></tr></thead>
            <tbody>
              @for (n of d.networks; track n.asn) {
                <tr><td class="mono">{{ n.asn }}</td><td>{{ n.as_name }}</td><td>{{ flag(n.country) }} {{ name(n.country) }}</td><td>{{ n.queries }}</td><td>{{ n.ips }}</td></tr>
              }
            </tbody>
          </table>
        </section>
      }
    } @else {
      <div class="blank"><p class="big-hint">Loading…</p></div>
    }`,
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
