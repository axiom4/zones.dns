import { Component, computed, input, output, signal } from '@angular/core';
import { geoNaturalEarth1, geoPath } from 'd3-geo';
import { feature } from 'topojson-client';
import { DestinationCountry, DestinationPoint } from '../api/models';
import { countryName } from '../lib/geo-util';
import { NUMERIC_TO_ALPHA2 } from '../lib/iso-numeric';

const W = 960, H = 500;

/** World map: countries shaded by how many queries point there, plus a bubble per city when coordinates are known. */
@Component({
  selector: 'app-geo-map',
  templateUrl: './geo-map.html',
})
export class GeoMap {
  W = W; H = H;
  countries = input.required<DestinationCountry[]>();
  points = input<DestinationPoint[]>([]);
  pick = output<string>(); // a shaded country was clicked

  private world = signal<any>(null);
  ready = computed(() => !!this.world());
  private projection = geoNaturalEarth1().fitSize([W, H], { type: 'Sphere' } as any);
  private path = geoPath(this.projection);

  constructor() {
    fetch('/world-110m.json').then(r => r.json()).then(w => this.world.set(w)).catch(() => {});
  }

  shapes = computed(() => {
    const w = this.world();
    if (!w) return [];
    const q = new Map(this.countries().map(c => [c.country, c.queries]));
    const max = Math.max(1, ...q.values());
    return (feature(w, w.objects.countries) as any).features.map((f: any, i: number) => {
      const code = NUMERIC_TO_ALPHA2[String(f.id ?? '').padStart(3, '0')] ?? '';
      const queries = q.get(code) ?? 0;
      return {
        id: f.id ?? `x${i}`, code, queries, d: this.path(f) ?? '',
        // darker the more queries point there; countries without traffic stay pale
        fill: queries ? `color-mix(in srgb, var(--brand) ${25 + Math.round((queries / max) * 70)}%, #ece8ff)` : null,
        title: `${f.properties?.name ?? countryName(code)}${queries ? ' · ' + queries + ' queries' : ''}`,
      };
    });
  });

  dots = computed(() => {
    const pts = this.points();
    const max = Math.max(1, ...pts.map(p => p.queries));
    return pts.flatMap(p => {
      const xy = this.projection([p.longitude, p.latitude]);
      return xy ? [{
        key: `${p.latitude},${p.longitude}`, x: xy[0], y: xy[1], r: 4 + Math.sqrt(p.queries / max) * 13,
        title: `${p.city || countryName(p.country)} · ${p.queries} queries · ${p.ips} addresses\n${p.domains.join(', ')}`,
      }] : [];
    });
  });
}
