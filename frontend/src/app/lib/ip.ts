/** Sort key for an address: IPv4 numerically (192.168.1.9 before 192.168.1.100), IPv6 after them as text. */
export function ipKey(ip: string): string {
  const p = ip.split('.');
  return p.length === 4 && p.every(x => /^\d{1,3}$/.test(x)) ? '4' + p.map(x => x.padStart(3, '0')).join('.') : '6' + ip;
}
export const byIp = (a: string, b: string) => ipKey(a).localeCompare(ipKey(b));
