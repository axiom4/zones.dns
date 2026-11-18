/** What to show for a failed API call: the strings of a DRF error body ({field: [msg]}, {detail}), else the HTTP message. */
export function errorText(e: any): string {
  const b = e?.error;
  // only strings: {detail, mfa_required: true} must not read "... true", a network error's ProgressEvent nor an HTML error page
  // must not become its own fields or letters
  const t = b && typeof b === 'object' ? Object.values(b).flat().filter(v => typeof v === 'string').join(' ') : '';
  return t || e?.message || 'Request failed.';
}

/** The per-field messages of a DRF validation error ({field: [msg]}), to show next to each input; detail/non_field_errors are left out. */
export function fieldErrors(e: any): Record<string, string> {
  const b = e?.error;
  if (!b || typeof b !== 'object' || Array.isArray(b)) return {};
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(b)) {
    const msgs = (Array.isArray(v) ? v : [v]).filter(x => typeof x === 'string');
    if (msgs.length && k !== 'detail' && k !== 'non_field_errors') out[k] = msgs.join(' ');
  }
  return out;
}
