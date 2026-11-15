"""The IPv6 hosts this machine knows on the network (the kernel's neighbour table, `ip -6 neigh`): the ones that configured themselves (SLAAC) leave no DHCP lease."""
import ipaddress
import os
import shutil
import subprocess

from ..models import Dhcp6Lease

def ip_command():
    """Path of `ip`: it lives in /sbin or /usr/sbin, which a service started by supervisor or systemd often has no PATH entry for. None when it is not installed."""
    return shutil.which('ip') or next((p for p in ('/usr/sbin/ip', '/sbin/ip', '/usr/bin/ip', '/bin/ip') if os.access(p, os.X_OK)), None)


GONE = {'FAILED', 'INCOMPLETE'}  # no link-layer address (yet) or the host did not answer


def parse(text):
    """[{'address', 'mac', 'interface', 'state'}] from the output of `ip -6 neigh`; entries without a MAC address are left out."""
    rows = []
    for line in text.splitlines():
        t = line.split()
        if len(t) < 5 or 'lladdr' not in t or 'dev' not in t or t[-1] in GONE:
            continue
        try:
            addr = ipaddress.IPv6Address(t[0])
        except ValueError:
            continue
        rows.append({'address': str(addr), 'mac': t[t.index('lladdr') + 1].lower(), 'interface': t[t.index('dev') + 1], 'state': t[-1]})
    return rows


def kind(row, leased):
    """Where the address comes from: 'link-local', 'dhcpv6' (a lease of ours), 'slaac' (EUI-64 built from the MAC), else 'other' (privacy or fixed address)."""
    addr = ipaddress.IPv6Address(row['address'])
    if addr.is_link_local:
        return 'link-local'
    if row['address'] in leased:
        return 'dhcpv6'
    b = addr.packed
    if b[11:13] == b'\xff\xfe' and ':'.join(f'{x:02x}' for x in (b[8] ^ 2, b[9], b[10], b[13], b[14], b[15])) == row['mac']:
        return 'slaac'
    return 'other'


def neighbors(interface=''):
    """The parsed table, each row with its kind. RuntimeError with the reason when `ip` is missing (not Linux) or fails."""
    ip = ip_command()
    if not ip:
        raise RuntimeError('The ip command is not installed (this needs Linux, package iproute2).')
    try:
        done = subprocess.run([ip, '-6', 'neigh', 'show'] + (['dev', interface] if interface else []), capture_output=True, text=True, timeout=3)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise RuntimeError(f'ip -6 neigh failed: {e}')
    if done.returncode:
        raise RuntimeError(f'ip -6 neigh failed: {done.stderr.strip() or done.returncode}')
    rows = parse(done.stdout)
    leased = set(Dhcp6Lease.objects.filter(kind__in=('na', 'ta')).values_list('value', flat=True))
    for r in rows:
        r['kind'] = kind(r, leased)
    return rows
