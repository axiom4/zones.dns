/** Flag emoji and English country name from an ISO 3166 code ("PRIV" = internal address, "??" = unknown). */
export function flag(code: string) {
  if (code === 'PRIV') return '🏠';
  if (!/^[A-Za-z]{2}$/.test(code) || code === '??') return '❔';
  return String.fromCodePoint(...[...code.toUpperCase()].map(c => 127397 + c.charCodeAt(0)));
}

let names: Intl.DisplayNames | null = null;
export function countryName(code: string) {
  if (code === 'PRIV') return 'Internal network';
  if (!/^[A-Za-z]{2}$/.test(code) || code === '??') return 'Unknown';
  try { names ??= new Intl.DisplayNames(['en'], { type: 'region' }); return names.of(code.toUpperCase()) ?? code; }
  catch { return code; }
}
