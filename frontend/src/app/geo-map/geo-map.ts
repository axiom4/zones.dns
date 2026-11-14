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

  // zoom: the visible part of the map (viewBox). k = magnification, (x, y) = top-left corner
  private view = signal({ k: 1, x: 0, y: 0 });
  viewBox = computed(() => { const v = this.view(); return `${v.x} ${v.y} ${W / v.k} ${H / v.k}`; });
  zoomed = computed(() => this.view().k > 1);
  private drag?: { px: number; py: number; moved: boolean };

  /** Zoom by `f` keeping the map point at (fx, fy) (0..1 across the visible area) where it is. */
  zoom(f: number, fx = .5, fy = .5) {
    this.view.update(v => {
      const k = Math.min(12, Math.max(1, v.k * f)), w = W / k, h = H / k;
      return this.clamp({ k, x: v.x + (W / v.k - w) * fx, y: v.y + (H / v.k - h) * fy });
    });
  }
  reset() { this.view.set({ k: 1, x: 0, y: 0 }); }
  private clamp(v: { k: number; x: number; y: number }) {
    return { k: v.k, x: Math.min(W - W / v.k, Math.max(0, v.x)), y: Math.min(H - H / v.k, Math.max(0, v.y)) };
  }
  wheel(e: WheelEvent) {
    e.preventDefault();
    const r = (e.currentTarget as SVGElement).getBoundingClientRect();
    // in proportion to the scroll: a trackpad sends many small events, each was a whole 1.25x step. About 1.1x per mouse wheel notch (deltaY ~100)
    const px = e.deltaY * (e.deltaMode === 1 ? 16 : e.deltaMode === 2 ? 400 : 1);
    this.zoom(Math.exp(-Math.max(-100, Math.min(100, px)) * 0.001), (e.clientX - r.left) / r.width, (e.clientY - r.top) / r.height);
  }
  down(e: PointerEvent) { this.drag = { px: e.clientX, py: e.clientY, moved: false }; }
  move(e: PointerEvent) {
    const d = this.drag;
    if (!d || !e.buttons) return;
    const r = (e.currentTarget as SVGElement).getBoundingClientRect(), v = this.view();
    const dx = e.clientX - d.px, dy = e.clientY - d.py;
    if (!d.moved && Math.hypot(dx, dy) < 4) return; // a click, not a drag
    d.moved = true; d.px = e.clientX; d.py = e.clientY;
    this.view.set(this.clamp({ k: v.k, x: v.x - dx * (W / v.k) / r.width, y: v.y - dy * (H / v.k) / r.height }));
  }
  up() { setTimeout(() => this.drag = undefined); } // after the click event of this release
  click(code: string, queries: number) { if (queries && !this.drag?.moved) this.pick.emit(code); }

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
        key: `${p.latitude},${p.longitude}`, x: xy[0], y: xy[1], r: (4 + Math.sqrt(p.queries / max) * 13) / Math.sqrt(this.view().k), // stay readable when zoomed
        title: `${p.city || countryName(p.country)} · ${p.queries} queries · ${p.ips} addresses\n${p.domains.join(', ')}`,
      }] : [];
    });
  });
}
