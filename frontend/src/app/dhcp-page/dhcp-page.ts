import { Component, ElementRef, computed, inject, input, signal, viewChild } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink, RouterLinkActive } from '@angular/router';
import { Api } from '../api/api';
import { dhcpLeasesDestroy, dhcpReservationsCreate, dhcpReservationsDestroy, dhcpReservations6Create, dhcpReservations6Destroy, dhcpReservationsList, dhcpReservations6List, dhcpLeasesList, dhcpSettingsPartialUpdate, dhcpSettingsRetrieve, statusRetrieve } from '../api/functions';
import { DhcpLease, DhcpSettings, Status } from '../api/models';
import { DaemonStatusLine } from '../daemon-status/daemon-status';
import { byIp } from '../lib/ip';
import { fieldErrors } from '../lib/error-text';
import { DhcpReservations } from '../dhcp-reservations/dhcp-reservations';
import { DhcpNeighbors } from '../dhcp-neighbors/dhcp-neighbors';
import { DhcpReservations6 } from '../dhcp-reservations6/dhcp-reservations6';
import { PingLive } from '../ping-live/ping-live';
import { pingSummary } from '../ping-live/ping-summary';
import { Ping } from '../services/ping';
import { StepUp } from '../services/step-up';
import { Ui } from '../services/ui';
import { SettingField, SettingsFields, changed } from './settings-fields';

interface Section { id: string; title: string; intro?: string; fields: SettingField[]; open?: (c: DhcpSettings) => boolean }

/** The DHCP settings, basics first; the rest in sections named by what the user wants to do. */
const BASICS: SettingField[] = [
  { key: 'DHCP', kind: 'check', label: 'Hand out IPv4 addresses', term: 'DHCPv4 server', wide: true, help: 'Only one DHCP server may run on a network: turn the router’s off first.' },
  { key: 'DHCP_SERVER', label: 'This server’s address', ph: 'e.g. 192.168.1.2', help: 'Its own IPv4 address on the network. Also the clients’ DNS server when “DNS servers” is empty.' },
  { key: 'DHCP_RANGE', label: 'Addresses to hand out', ph: 'e.g. 192.168.1.100-192.168.1.200', help: 'First and last address, as first-last, inside the network.' },
  { key: 'DHCP_ROUTER', label: 'Gateway', term: 'router', ph: 'e.g. 192.168.1.1', help: 'Where clients send traffic for the internet. Empty: none sent.' },
  { key: 'DHCP_NETMASK', label: 'Netmask', ph: 'e.g. 255.255.255.0', help: '255.255.255.0 for a /24 network.' },
  { key: 'DHCP_DNS', label: 'DNS servers for clients', ph: 'empty: this server', help: 'Several allowed, separated by spaces or commas. Empty: this server’s address.' },
  { key: 'DHCP_DOMAIN', label: 'Local domain', ph: 'e.g. lan', help: 'Devices get names like nas.lan.' },
  { key: 'DHCP_LEASE', kind: 'number', min: 60, label: 'Lease time (seconds)', ph: 'e.g. 3600', help: 'How long a device keeps its address before renewing. 3600 = 1 hour, 86400 = 1 day.' },
  { key: 'DHCP_INTERFACE', label: 'Network interface', ph: 'e.g. eth0', help: 'Needed for IPv6, the neighbour list and “Reply straight to the device”.' },
  { key: 'DHCP_NAMES', kind: 'check', label: 'Answer device names in DNS', wide: true, help: 'The name a device gives (nas.lan) resolves to its address. A zone record of the same type wins.' },
];
const SECTIONS: Section[] = [
  { id: 'opts', title: 'More options for IPv4 devices', fields: [
    { key: 'DHCP_SEARCH', label: 'Search domains', ph: 'empty: the local domain', help: 'Tried when you type a short name, separated by spaces.' },
    { key: 'DHCP_NTP', label: 'Time servers', term: 'NTP', ph: 'empty: none', help: 'Several allowed, separated by spaces or commas.' },
    { key: 'DHCP_MTU', kind: 'number', min: 0, max: 65535, label: 'Packet size', term: 'MTU', ph: '0: not sent', help: '0 = not sent, otherwise 68 to 65535.' },
    { key: 'DHCP_ROUTES', label: 'Extra routes', term: 'static routes', wide: true, ph: 'e.g. 10.0.0.0/8=192.168.1.254', help: 'network/length=gateway, separated by spaces. The gateway must be inside the network.' },
    { key: 'DHCP_DNR', kind: 'check', label: 'Announce encrypted DNS', term: 'DNR', help: 'Devices that support it switch to DoT/DoH by themselves. Needs DNS_DDR in .env.' },
  ] },
  { id: 'v6', title: 'IPv6 addresses', intro: 'Needs a network interface (in the basics).', open: c => !!c.DHCP6, fields: [
    { key: 'DHCP6', kind: 'check', label: 'Hand out IPv6 addresses', term: 'DHCPv6 server', wide: true, help: 'With an address pool it hands out addresses; with DNS servers only, it just tells devices where DNS is.' },
    { key: 'DHCP6_PREFIX', label: 'Network prefix', ph: 'e.g. fd4c:61da:7888:bc1a::/64', help: 'The /64 of the network. Also announced to IPv6 devices.' },
    { key: 'DHCP6_POOL', label: 'Addresses to hand out', term: 'IA_NA', wide: true, ph: 'first-last', help: 'Inside the prefix. Empty: devices build their own address (SLAAC).' },
    { key: 'DHCP6_DNS', label: 'DNS servers for clients', ph: 'IPv6 addresses', help: 'Several allowed, separated by spaces or commas.' },
    { key: 'DHCP6_LEASE', kind: 'number', min: 120, label: 'Lease time (seconds)', help: 'At least 120.' },
    { key: 'DHCP6_PD_POOL', label: 'Prefixes for other routers', term: 'prefix delegation', ph: 'e.g. 2001:db8:ff00::/40', help: 'Network that prefixes are cut from when a router asks for one. Empty: none.' },
    { key: 'DHCP6_PD_LEN', kind: 'number', min: 1, max: 64, label: 'Size of each prefix', ph: 'e.g. 56', help: 'Longer than the pool’s prefix, at most 64.' },
    { key: 'DHCP6_PREFERENCE', kind: 'number', min: 0, max: 255, label: 'Server priority', term: '0–255', help: '255 = chosen at once; lower makes this a backup. 0 = not sent.' },
    { key: 'DHCP6_RAPID', kind: 'check', label: 'Faster address handout', term: 'rapid commit', help: 'Two messages instead of four, for devices that ask for it.' },
    { key: 'DHCP6_PD_ROUTES', kind: 'check', label: 'Add routes to delegated prefixes', help: 'Adds a kernel route to each router that got a prefix. Linux, needs root.' },
  ] },
  { id: 'ra', title: 'Announce the IPv6 network', intro: 'Router Advertisements tell every IPv6 device the prefix, the DNS servers and whether to ask this server for an address.', open: c => !!c.DHCP_RA, fields: [
    { key: 'DHCP_RA', kind: 'check', label: 'Announce the IPv6 network', term: 'Router Advertisements', wide: true, help: 'Needs a network interface and root or CAP_NET_RAW.' },
    { key: 'DHCP_RA_INTERVAL', kind: 'number', min: 4, max: 1800, label: 'Every (seconds)', help: '4 to 1800. A device that joins gets one at once.' },
    { key: 'DHCP_RA_ROUTER_LIFETIME', kind: 'number', min: 0, max: 9000, label: 'Act as IPv6 gateway (seconds)', term: 'router lifetime', ph: '0: not a gateway', help: 'Leave 0 unless this server really routes IPv6: above 0 devices send it their IPv6 traffic.' },
    { key: 'DHCP_RA_SLAAC', kind: 'check', label: 'Let devices build their own address', term: 'SLAAC', help: 'Needs a /64. Off: addresses only from this server.' },
  ] },
  { id: 'pxe', title: 'Network boot', intro: 'For computers that start from the network (PXE).', fields: [
    { key: 'DHCP_BOOT_SERVER', label: 'Boot server', term: 'TFTP', help: 'Address or name of the TFTP server. Empty: none.' },
    { key: 'DHCP_BOOT_FILE', label: 'Boot file', help: 'File the computer loads from the boot server. Empty: none.' },
  ] },
  { id: 'relay', title: 'Other networks through a relay', fields: [
    { key: 'DHCP_SUBNETS', kind: 'textarea', label: 'Relayed networks', term: 'JSON', ph: '[{"network": "10.1.0.0/24", "range": "10.1.0.10-10.1.0.99"}]',
      help: 'A JSON list; each item needs network and range, and may set router, dns, domain, lease, ntp, search, routes, mtu, boot_server, boot_file.' },
    { key: 'DHCP_LEASEQUERY', label: 'Who may ask who holds an address', term: 'Leasequery', wide: true, ph: 'empty: nobody', help: 'Addresses or networks, e.g. a relay agent. Separated by spaces or commas.' },
  ] },
  { id: 'rel', title: 'Reliability', fields: [
    { key: 'DHCP_PROBE', kind: 'check', label: 'Check an address is free before handing it out', help: 'Avoids duplicates; adds a short delay to each new device.' },
    { key: 'DHCP_UNICAST', kind: 'check', label: 'Reply straight to the device', help: 'Instead of broadcasting. Linux only, needs root or CAP_NET_RAW and a network interface.' },
    { key: 'DHCP_FAILOVER_SECS', kind: 'number', min: 0, label: 'Backup server delay (seconds)', term: 'failover', ph: '0: this is the main server', help: 'On a backup server: answer a new device only after this wait, so the main one goes first.' },
  ] },
];

@Component({
  selector: 'app-dhcp-page',
  imports: [FormsModule, RouterLink, RouterLinkActive, DhcpReservations, DhcpReservations6, DhcpNeighbors, PingLive, SettingsFields, DaemonStatusLine],
  templateUrl: './dhcp-page.html',
})
export class DhcpPage {
  private api = inject(Api);
  private ui = inject(Ui);
  private stepUp = inject(StepUp);
  ping = inject(Ping);
  live = viewChild(PingLive);
  private dlg = viewChild<ElementRef<HTMLDialogElement>>('cfgdlg');
  readonly basics = BASICS;
  readonly sections = SECTIONS;
  leases = signal<DhcpLease[]>([]);
  loaded = signal(false);
  status = signal<Status | null>(null); // is rundhcp running (its heartbeat)
  cfg = signal<DhcpSettings>({});
  private savedCfg: DhcpSettings = {};
  errs = signal<Record<string, string>>({});
  section = input('leases', { alias: 'tab' }); // the :tab of the route /dhcp/:tab
  tab = computed(() => (['leases', 'leases6', 'reservations', 'reservations6', 'neighbors'].includes(this.section()) ? this.section() : 'leases'));
  /** One filter for every tab: a device is found by name, address, MAC, DUID or maker wherever it shows. */
  q = signal('');
  shown = computed(() => {
    const q = this.q().trim().toLowerCase(), fam = this.tab() === 'leases6' ? 6 : 4;
    return this.leases().filter(l => l.family === fam && (!q || `${l.address} ${l.mac} ${l.client} ${l.hostname} ${l.vendor}`.toLowerCase().includes(q)));
  });
  reserved = signal(new Set<string>()); // MACs and addresses that already have a reservation
  all = false;

  constructor() { this.load(); }

  load() {
    return this.ui.run(async () => {
      const [leases, res, res6] = await Promise.all([
        this.api.invoke(dhcpLeasesList, { all: this.all || undefined }),
        this.api.invoke(dhcpReservationsList),
        this.api.invoke(dhcpReservations6List),
      ]);
      this.status.set(await this.api.invoke(statusRetrieve).catch(() => null)); // unreadable: the line says “checking”, the leases still show
      this.leases.set([...leases].sort((a, b) => byIp(a.address, b.address)));
      this.reserved.set(new Set([...res.flatMap(r => [r.mac, r.ip]), ...res6.flatMap(r => [r.duid, r.ip])]));
      this.loaded.set(true);
    });
  }

  /** Opens the settings with what the server has now (not edits left from a dialog closed without saving). */
  openSettings() {
    return this.ui.run(async () => {
      const cfg = await this.api.invoke(dhcpSettingsRetrieve);
      this.savedCfg = structuredClone(cfg);
      this.cfg.set(cfg);
      this.errs.set({});
      this.dlg()?.nativeElement.showModal();
    });
  }
  dirty() { return changed(this.savedCfg, this.cfg()).length > 0; }
  /** Close button and Esc: ask before throwing changes away. */
  closeSettings(e?: Event) {
    e?.preventDefault();
    const dlg = this.dlg()!.nativeElement;
    if (!this.dirty()) { dlg.close(); return; }
    this.ui.ask('Discard your changes?', 'The DHCP settings you changed are not saved.', () => dlg.close(), 'Discard changes');
  }
  hasErr(s: Section) { return s.fields.some(f => this.errs()[f.key]); }
  sectionOpen(s: Section) { return !!s.open?.(this.cfg()) || this.hasErr(s); }

  saveSettings() {
    const was = this.savedCfg, now = this.cfg(), risks: string[] = [];
    if (!was.DHCP && now.DHCP) risks.push('The IPv4 server goes on. Only one DHCP server may run on a network: if the router still hands out addresses, devices may get wrong ones.');
    if (!was.DHCP_RA_ROUTER_LIFETIME && (now.DHCP_RA_ROUTER_LIFETIME ?? 0) > 0) risks.push('IPv6 devices will send their internet traffic to this server. Do this only if it really routes IPv6.');
    if (!risks.length) return this.doSave();
    this.ui.ask(risks.length > 1 ? 'Save these risky changes?' : 'Save this risky change?', risks.join(' '), () => this.doSave(), 'Save settings');
    return undefined;
  }
  private doSave() {
    return this.ui.run(async () => {
      // the gateway, DNS, routes, boot server, Leasequery... need a second factor (scope dhcp-change): asked only when the server says so
      const save = (g?: string) => this.api.invoke(dhcpSettingsPartialUpdate, { body: this.cfg(), 'X-MFA-Grant': g });
      this.errs.set({});
      let cfg: DhcpSettings;
      try {
        try {
          cfg = await save();
        } catch (e: any) {
          if (e?.status !== 403 || !e?.error?.mfa_required) throw e;
          const grant = await this.stepUp.request('dhcp-change', 'Change the DHCP settings', 'Save settings');
          if (grant === null) return;
          cfg = await save(grant || undefined);
        }
      } catch (e) { this.errs.set(fieldErrors(e)); throw e; }
      this.savedCfg = structuredClone(cfg);
      this.cfg.set(cfg);
      this.dlg()?.nativeElement.close();
      this.ui.toast('DHCP settings saved and applied');
    });
  }

  /** Makes the address of a lease fixed for its device (MAC, or DUID for IPv6) at once; Undo deletes the reservation again. */
  fix(l: DhcpLease) {
    const who = l.hostname || l.client;
    return this.ui.run(async () => {
      const r = l.family === 4
        ? await this.api.invoke(dhcpReservationsCreate, { body: { mac: l.client, ip: l.address, hostname: l.hostname } })
        : await this.api.invoke(dhcpReservations6Create, { body: { duid: l.client, ip: l.address } });
      await this.load();
      this.ui.toast(`Reserved ${l.address} for ${who}`, async () => {
        await (l.family === 4 ? this.api.invoke(dhcpReservationsDestroy, { id: r.id }) : this.api.invoke(dhcpReservations6Destroy, { id: r.id }));
        await this.load();
      });
    });
  }
  watch(l: DhcpLease) { this.live()?.open(l.address); }
  pingOne(l: DhcpLease) { return this.ui.run(async () => { await this.ping.once(l.address); this.ui.toast(`${l.address}: ${this.ping.label(l.address)}`); }); }
  pingAll() {
    const list = this.shown().filter(l => l.active && l.kind === 'address').map(l => l.address);
    return this.ui.run(async () => { await this.ping.run(list); this.ui.toast(pingSummary(this.ping, list)); });
  }
  isReserved(l: DhcpLease) { return this.reserved().has(l.client) || this.reserved().has(l.address); }
  when(iso: string) { return new Date(iso).toLocaleString(); }
  end(l: DhcpLease) {
    this.ui.ask(`End the lease of ${l.address}?`, 'The address is free again. The device keeps it until it renews, and is then told it cannot.', () =>
      this.ui.run(async () => { await this.api.invoke(dhcpLeasesDestroy, { family: l.family, id: l.id }); await this.load(); }, { ok: `Ended the lease of ${l.address}` }), 'End lease');
  }
}
