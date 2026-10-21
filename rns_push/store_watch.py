import os
import threading
import time

import RNS

HASH_LENGTH = 16


class MessageStoreWatcher:
    """Reports files that appear in lxmd's message store for registered destinations.

    Each file is named `<transient id>_<received>[_<stamp value>]` and begins with the
    recipient's 16-byte delivery destination hash, unencrypted. The store holds on the order
    of 200k files on a router, so an unchanged directory mtime skips the listing entirely."""

    def __init__(self, path, registry, on_arrival, clock=time.time, interval=3.0, seen_ttl=86400.0):
        self.path = path
        self.registry = registry
        self.on_arrival = on_arrival
        self.clock = clock
        self.interval = interval
        self.seen_ttl = seen_ttl
        self._seen = {}
        self._baselined = False
        self._dir_mtime_ns = None
        self._stopped = threading.Event()

    def start(self):
        threading.Thread(target=self._loop, daemon=True).start()

    def stop(self):
        self._stopped.set()

    def poll(self):
        """One pass over the store. Returns the number of arrivals reported."""
        try:
            mtime_ns = os.stat(self.path).st_mtime_ns
        except OSError:
            return 0
        if mtime_ns == self._dir_mtime_ns:
            return 0
        try:
            with os.scandir(self.path) as entries:
                listed = {}
                for entry in entries:
                    transient_id, separator, _ = entry.name.partition("_")
                    if separator:
                        listed[transient_id] = entry.name
        except OSError:
            return 0
        # Taken before the listing, so a file added during it is seen on the next pass.
        self._dir_mtime_ns = mtime_ns

        now = self.clock()
        arrivals = 0
        if not self._baselined:
            self._baselined = True
            for transient_id in listed:
                self._seen[transient_id] = now
            return 0
        for transient_id, name in listed.items():
            if transient_id in self._seen:
                continue
            self._seen[transient_id] = now
            destination_hash = self._recipient(name)
            if destination_hash is not None and self.registry.get(destination_hash) is not None:
                self.on_arrival(destination_hash)
                arrivals += 1
        stale = [t for t, at in self._seen.items() if t not in listed and now - at >= self.seen_ttl]
        for transient_id in stale:
            del self._seen[transient_id]
        return arrivals

    def _recipient(self, name):
        try:
            with open(os.path.join(self.path, name), "rb") as f:
                head = f.read(HASH_LENGTH)
        except OSError:
            return None
        return head if len(head) == HASH_LENGTH else None

    def _loop(self):
        while not self._stopped.is_set():
            try:
                self.poll()
            except Exception as e:
                RNS.log(f"Message store poll failed: {e}", RNS.LOG_ERROR)
            self._stopped.wait(self.interval)
