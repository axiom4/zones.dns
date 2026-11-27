"""A worker's memory: a line in the log on what it holds, the places it allocated once it grows, and an exit before it takes the
machine's RAM. A worker that grew by gigabytes in minutes filled the RAM and the swap and froze the server: ping still answered,
SSH, DHCP and DNS did not. The Raspberry Pi kernel starts with cgroup_disable=memory, so systemd's MemoryMax would not stop it."""
import asyncio
import os
import tracemalloc

import h2.events

EVERY = 10.0              # seconds between readings
QUIET = 900.0             # a line every 15 minutes while the worker is small
BIG = 512 * 2**20         # above it: allocations are traced, a line a minute (or every STEP more) with the places that hold the most
STEP = 100 * 2**20
LIMIT = 1536 * 2**20      # above it the worker exits; the supervisor (or systemd) starts it again


def rss():
    """The resident memory of this process in bytes, None where there is no /proc (not Linux)."""
    try:
        with open('/proc/self/statm') as f:
            return int(f.read().split()[1]) * os.sysconf('SC_PAGE_SIZE')
    except (OSError, ValueError, IndexError):
        return None


def report(server, rss_bytes):
    """Memory, client connections (the three addresses with most), upstream connections and the response data their HTTP/2 streams
    received but nobody has read yet. Must run on the server's event loop."""
    pool = getattr(server, '_upstream_pool', None)
    conns = list(getattr(pool, 'connections', None) or ())
    streams = buffered = 0
    for c in conns:
        for events in (getattr(getattr(c, '_connection', None), '_events', None) or {}).values():
            streams += 1
            buffered += sum(len(e.data or b'') for e in events if isinstance(e, h2.events.DataReceived))
    top = sorted(server._per_client.items(), key=lambda kv: -kv[1])[:3]
    clients = ', '.join(f'{ip} {n}' for ip, n in top) or 'none'
    return (f'Proxy worker {os.getpid()}: {rss_bytes / 2**20:.0f} MB, {server._total} client connections ({clients}), '
            f'{len(conns)} upstream connections, {streams} HTTP/2 streams holding {buffered / 2**20:.1f} MB unread, '
            f'{len(asyncio.all_tasks())} tasks')


def allocations(n=8):
    """The `n` source lines holding the most memory allocated since tracing started."""
    stats = tracemalloc.take_snapshot().statistics('lineno')[:n]
    return '; '.join(f'{s.traceback[0].filename.rsplit("/site-packages/", 1)[-1]}:{s.traceback[0].lineno} '
                     f'{s.size / 2**20:.1f} MB in {s.count}' for s in stats)


async def watch(server, write):
    """Runs for the life of the worker. `write` takes one line."""
    loop = asyncio.get_running_loop()
    last_t, last_rss = float('-inf'), 0
    while True:
        await asyncio.sleep(EVERY)
        r = rss()
        if r is None:
            return
        now = loop.time()
        try:
            if r < BIG:
                if tracemalloc.is_tracing():
                    tracemalloc.stop()
                if now - last_t >= QUIET:
                    write(report(server, r))
                    last_t, last_rss = now, r
                continue
            started = not tracemalloc.is_tracing()
            if started:
                tracemalloc.start()
            if started or r >= LIMIT or now - last_t >= 60.0 or r - last_rss >= STEP:
                line = report(server, r)
                if not started:
                    line += ' | held since tracing started: ' + allocations()
                write(line)
                last_t, last_rss = now, r
        except Exception as e:  # the report reads httpcore's private state: it must never stop the worker
            write(f'Proxy worker {os.getpid()}: memory report failed: {e!r}')
        if r >= LIMIT:
            write(f'Proxy worker {os.getpid()}: {r / 2**20:.0f} MB is over the {LIMIT / 2**20:.0f} MB limit: exiting, to be started again')
            os._exit(70)
