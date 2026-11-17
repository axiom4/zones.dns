"""One log format for every process: the date first ("2026-11-17 15:38:26 ..."). Supervisor files then sort and read the same way."""
import sys
import threading
import time


class _Stamped:
    """A text stream that starts every line with the date and time."""

    def __init__(self, out):
        self._out, self._lock, self._fresh = out, threading.Lock(), True

    def write(self, text):
        with self._lock:
            for line in text.splitlines(keepends=True):
                if self._fresh and line.strip():
                    self._out.write(time.strftime('%Y-%m-%d %H:%M:%S '))
                self._out.write(line)
                self._fresh = line.endswith('\n')
        return len(text)

    def __getattr__(self, name):
        return getattr(self._out, name)


def stamp_output(cmd):
    """For the long-running commands (rundns, rundhcp, runproxy): stdout and stderr, and Django's self.stdout / self.stderr, get the date."""
    sys.stdout, sys.stderr = _Stamped(sys.stdout), _Stamped(sys.stderr)
    cmd.stdout._out, cmd.stderr._out = sys.stdout, sys.stderr
