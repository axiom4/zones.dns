import { Ping } from '../services/ping';

/** What "Ping all" found, in one sentence for the notice (read out by screen readers): "5 of 7 answered". */
export function pingSummary(ping: Ping, addresses: string[]) {
  const list = [...new Set(addresses.filter(a => !!a))];
  if (!list.length) return 'Nothing to ping';
  const up = list.filter(a => ping.results()[a]?.up).length;
  return `${up} of ${list.length} ${list.length === 1 ? 'address' : 'addresses'} answered`;
}
