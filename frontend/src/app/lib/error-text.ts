/** What to show for a failed API call: the strings of a DRF error body ({field: [msg]}, {detail}), else the HTTP message. */
export function errorText(e: any): string {
  const b = e?.error;
  // only strings: {detail, mfa_required: true} must not read "... true", a network error's ProgressEvent nor an HTML error page
  // must not become its own fields or letters
  const t = b && typeof b === 'object' ? Object.values(b).flat().filter(v => typeof v === 'string').join(' ') : '';
  return t || e?.message || 'Request failed.';
}
