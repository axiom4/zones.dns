/** Minutes shown by the activity strip. */
export const MINUTES = 60;

interface Bucket { t: string; count: number; blocked: number; proxy_blocked: number }

/** 60 per-minute totals ending at the current minute; minutes without a bucket count 0. */
export function byMinute(series: Bucket[], now: number): [number[], number[]] {
  const c = new Array(MINUTES).fill(0), b = new Array(MINUTES).fill(0);
  const end = Math.floor(now / 60000);
  for (const s of series) {
    const i = MINUTES - 1 - (end - Math.floor(Date.parse(s.t) / 60000));
    if (i >= 0 && i < MINUTES) { c[i] += s.count; b[i] += s.blocked + s.proxy_blocked; }
  }
  return [c, b];
}
