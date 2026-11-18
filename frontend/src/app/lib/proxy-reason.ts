/** Which layer blocked a proxy request, from the reason of its log row ("blacklist: ads.example (easylist)", "ad-url: /pagead/"…); '' when it says none. */
export function blockLayer(reason: string): string {
  const m = /^([a-z-]+): (.*)$/s.exec(reason || '');
  if (!m) return '';
  const at = m[2].indexOf(' ('), from = at >= 0 && m[2].endsWith(')') ? m[2].slice(at + 2, -1) : ''; // "name (where)": the name has no space, a pattern may have ( )
  switch (m[1]) {
    case 'blacklist': return `DNS blocklist: ${from === 'personal' ? 'Personal blocks' : from || 'blocklist'}`;
    case 'rule-list': return `Ad-block list: ${from || 'list'}`;
    case 'ad-url': return 'Ad rule';
    case 'popup-url': return 'Popup rule';
    case 'custom-rule': return 'Your rule';
    default: return '';
  }
}
