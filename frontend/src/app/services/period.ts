import { Injectable } from '@angular/core';

const KEY = 'period.hours';

/** The time window (in hours: 1, 24, 168, 720; 0 = all time) last chosen in any page that has a period filter: every such page starts with it. */
@Injectable({ providedIn: 'root' })
export class Period {
  private last(): number | null {
    const v = localStorage.getItem(KEY);
    return v !== null && [0, 1, 24, 168, 720].includes(Number(v)) ? Number(v) : null;
  }

  remember(hours: number) {
    if ([0, 1, 24, 168, 720].includes(hours)) localStorage.setItem(KEY, String(hours));
  }

  /** The remembered period as one of the `allowed` ones (a page that has no "all time" takes its longest, one with fewer windows the nearest longer one); `fallback` when nothing is remembered. */
  pick(allowed: number[], fallback = 24): number {
    const s = this.last() ?? fallback;
    if (allowed.includes(s)) return s;
    const longer = allowed.filter(a => a > s && a !== 0).sort((a, b) => a - b);
    return s === 0 || !longer.length ? Math.max(...allowed) : longer[0];
  }
}
