/** IPv4 helpers for reverse zones. IPv6 is left to the server (nibble names are error-prone to preview). */

export function cidrToZone(cidr: string): string | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(8|16|24)$/.exec(cidr.trim());
  if (!m) return null;
  const octets = m.slice(1, 5).map(Number);
  if (octets.some(o => o > 255)) return null;
  const keep = Number(m[5]) / 8;
  if (octets.slice(keep).some(o => o !== 0)) return null; // host bits set
  return [...octets.slice(0, keep)].reverse().join('.') + '.in-addr.arpa';
}

/** PTR record name inside an IPv4 reverse zone -> the address it describes, if complete. */
export function ptrToIp(zoneName: string, rel: string): string | null {
  if (!zoneName.endsWith('.in-addr.arpa')) return null;
  const labels = [...rel.split('.'), ...zoneName.split('.').slice(0, -2)];
  return labels.length === 4 && labels.every(l => /^\d{1,3}$/.test(l)) ? labels.reverse().join('.') : null;
}
