"""Writes the query log in batches, off the path that answers queries.

resolve() puts the log row in a queue and answers at once; this thread saves what has piled up with one bulk INSERT every
DNS_LOG_FLUSH seconds. If the process dies suddenly, the rows still in the queue (at most about one second) are lost.
"""
import logging
import queue
import threading

from django.db import close_old_connections

from .models import QueryLog

log = logging.getLogger(__name__)


class LogWriter:
    def __init__(self, interval=1.0, queue_max=50000, batch_max=1000):
        self.interval, self.batch_max, self.queue_max = interval, batch_max, queue_max
        self.queue = queue.Queue(maxsize=queue_max)
        self.dropped = 0
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name='dns-logwriter', daemon=True)
        self._retry = []  # rows a failed INSERT left behind, tried again at the next round

    def start(self):
        self._thread.start()

    def add(self, entry):
        try:
            self.queue.put_nowait(entry)
        except queue.Full:  # the database cannot keep up: losing log lines is better than slowing or stopping DNS answers
            self.dropped += 1

    def stop(self):
        """Save what is left, then end."""
        self._stop.set()
        self._thread.join(timeout=30)

    def _run(self):
        while not self._stop.wait(self.interval):
            self._flush()
        self._flush()

    def _flush(self):
        rows, self._retry = self._retry, []
        try:
            while True:
                rows.append(self.queue.get_nowait())
        except queue.Empty:
            pass
        if not rows:
            return
        try:
            close_old_connections()
            for i in range(0, len(rows), self.batch_max):
                QueryLog.objects.bulk_create(rows[i:i + self.batch_max])
        except Exception:
            log.exception('query log: saving %d rows failed, will retry', len(rows))
            self._retry = rows[-self.queue_max:]  # bounded, newest kept
