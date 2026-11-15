"""Is a host of the network up: one ICMP echo with the system's `ping` (no raw socket, no privileges)."""
import ipaddress
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

MAX_HOSTS = 64
TIME = re.compile(r'time[=<]\s*([\d.]+)')


def allowed(ip):
    """Only addresses of a local network (private, link-local, unique local): this server must not be a tool to probe the Internet."""
    return ip.is_private and not ip.is_unspecified and not ip.is_multicast


def ping_one(ip, timeout=1):
    """(up, milliseconds or None) for an ipaddress object."""
    if ip.version == 6:
        cmd = ['ping6', '-c', '1', str(ip)] if sys.platform == 'darwin' else ['ping', '-6', '-c', '1', '-W', str(timeout), str(ip)]
    else:
        cmd = ['ping', '-c', '1', '-W', str(timeout * 1000 if sys.platform == 'darwin' else timeout), str(ip)]  # -W: milliseconds on macOS, seconds on Linux
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 3)
    except (OSError, subprocess.TimeoutExpired):
        return False, None
    m = TIME.search(r.stdout)
    return r.returncode == 0, (round(float(m.group(1)), 1) if m and r.returncode == 0 else None)


def ping_many(addresses):
    """[{'address', 'up', 'ms', 'error'}] in the order given. A name, a public address or too many hosts get an error instead of a ping."""
    out, todo = [], []
    for a in addresses[:MAX_HOSTS]:
        try:
            ip = ipaddress.ip_address(str(a).strip())
        except ValueError:
            out.append({'address': str(a)[:64], 'up': False, 'ms': None, 'error': 'Not an IP address.'})
            continue
        if not allowed(ip):
            out.append({'address': str(ip), 'up': False, 'ms': None, 'error': 'Only addresses of a local network can be pinged.'})
            continue
        out.append({'address': str(ip), 'up': False, 'ms': None, 'error': ''})
        todo.append((len(out) - 1, ip))
    with ThreadPoolExecutor(max_workers=16) as pool:
        for (i, _), (up, ms) in zip(todo, pool.map(lambda t: ping_one(t[1]), todo)):
            out[i].update(up=up, ms=ms)
    return out
