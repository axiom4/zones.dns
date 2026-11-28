"""A worker's memory: a line in the log on what it holds, the places it allocated once it grows, and an exit before it takes the
machine's RAM. A worker that grew by gigabytes in minutes filled the RAM and the swap and froze the server: ping still answered,
SSH, DHCP and DNS did not.

The limit and the stall check run in a thread of their own: the growth came with the event loop stuck at 100% CPU in a loop of the
proxy's code, and a check on the event loop never ran again (the kernel killed the workers at 1.4 to 2.7 GB, nothing in the log).
The thread writes where the event loop is stuck, so the log names the code."""
import asyncio
import os
import sys
import threading
import time
import traceback
import tracemalloc

import h2.events

EVERY = 10.0              # seconds between readings of watch()
QUIET = 900.0             # a line every 15 minutes while the worker is small
BIG = 512 * 2**20         # above it: allocations are traced, a line a minute (or every STEP more) with the places that hold the most
STEP = 100 * 2**20
LIMIT = 1536 * 2**20      # above it the worker exits (guard thread); the supervisor (or systemd) starts it again
STALL = 5.0               # seconds the event loop may not run before the guard writes where it is


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


def where(thread_id, depth=15):
    """What thread `thread_id` is running, innermost last: 'file:line function > ...'."""
    frame = sys._current_frames().get(thread_id)
    if frame is None:
        return 'unknown'
    return ' > '.join(f'{f.filename.rsplit("/site-packages/", 1)[-1].rsplit("/backend/", 1)[-1]}:{f.lineno} {f.name}'
                      for f in traceback.extract_stack(frame)[-depth:])


async def watch(server, write):
    """Runs on the event loop for the life of the worker: the report lines and the allocation tracing. `write` takes one line."""
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
            if started or now - last_t >= 60.0 or r - last_rss >= STEP:
                line = report(server, r)
                if not started:
                    line += ' | held since tracing started: ' + allocations()
                write(line)
                last_t, last_rss = now, r
        except Exception as e:  # the report reads httpcore's private state: it must never stop the worker
            write(f'Proxy worker {os.getpid()}: memory report failed: {e!r}')


def guard(loop_thread, beat, write, every=1.0):
    """Runs in a thread of its own: every `every` seconds the memory and how long ago the event loop last ran (`beat[0]`, monotonic).
    A stuck event loop gets one line with where it is; over LIMIT the worker writes where the event loop is and exits."""
    stalled = False
    while True:
        time.sleep(every)
        r = rss()
        if r is None:
            return
        idle = time.monotonic() - beat[0]
        if (idle >= STALL and not stalled) or r >= LIMIT:
            write(f'Proxy worker {os.getpid()}: {r / 2**20:.0f} MB, the event loop last ran {idle:.0f} s ago; it is at {where(loop_thread)}')
        stalled = idle >= STALL
        if r >= LIMIT:
            write(f'Proxy worker {os.getpid()}: {r / 2**20:.0f} MB is over the {LIMIT / 2**20:.0f} MB limit: exiting, to be started again')
            os._exit(70)


def start(server, write):
    """On the worker's event loop: watch(), the beat the guard looks at, and the guard thread. Returns the tasks (keep them)."""
    loop = asyncio.get_running_loop()
    beat = [time.monotonic()]

    async def beating():
        while True:
            beat[0] = time.monotonic()
            await asyncio.sleep(1.0)
    threading.Thread(target=guard, args=(threading.get_ident(), beat, write), name='proxy-memguard', daemon=True).start()
    return loop.create_task(beating()), loop.create_task(watch(server, write))
