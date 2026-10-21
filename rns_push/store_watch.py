import os
import threading
import time

import RNS

HASH_LENGTH = 16
SHORT_GRACE = 60.0


class MessageStoreWatcher:
    """Reports files that appear in lxmd's message store for registered destinations.

    Each file is named `<transient id>_<received>[_<stamp value>]` and begins with the
    recipient's 16-byte delivery destination hash, unencrypted. The store holds on the order
    of 200k files on a router, so an unchanged directory mtime skips the listing entirely.

    `clock` times the `seen` TTL, a duration, so it is monotonic; `wall_clock` is compared
    with the directory's mtime."""

    def __init__(self, path, registry, on_arrival, clock=time.monotonic, interval=3.0, seen_ttl=86400.0,
                 wall_clock=time.time):
        self.path = path
        self.registry = registry
        self.on_arrival = on_arrival
        self.clock = clock
        self.wall_clock = wall_clock
        self.interval = interval
        self.seen_ttl = seen_ttl
        self._seen = {}
        self._short = {}
        self._baselined = False
        self._dir_mtime_ns = None
        self._unavailable = False
        self._stopped = threading.Event()
        self._thread = None

    def start(self):
        if self._thread is not None and self._thread.is_alive():
            return
        self._stopped.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._stopped.set()
        if self._thread is not None and self._thread is not threading.current_thread():
            self._thread.join(timeout=5.0)

    def poll(self):
        """One pass over the store. Returns the number of arrivals reported."""
        try:
            mtime_ns = os.stat(self.path).st_mtime_ns
        except OSError as e:
            self._fail(e)
            # A store that comes back is a new one: baseline it rather than push all of it.
            self._baselined = False
            self._dir_mtime_ns = None
            self._seen.clear()
            self._short.clear()
            return 0
        if mtime_ns == self._dir_mtime_ns:
            return 0
        try:
            with os.scandir(self.path) as entries:
                # Ids are kept as bytes and names only for unseen ids: the store is huge, and
                # a string per file would cost a router most of its memory.
                listed = set()
                unseen = {}
                for entry in entries:
                    transient_id, separator, _ = entry.name.partition("_")
                    if not separator:
                        continue
                    try:
                        transient_id = bytes.fromhex(transient_id)
                    except ValueError:
                        continue
                    listed.add(transient_id)
                    if self._baselined and transient_id not in self._seen:
                        unseen[transient_id] = entry.name
        except OSError as e:
            self._fail(e)
            return 0
        self._unavailable = False

        now = self.clock()
        arrivals = 0
        incomplete = False
        if not self._baselined:
            self._baselined = True
            for transient_id in listed:
                self._seen[transient_id] = now
            RNS.log(f"Watching {len(listed)} messages in {self.path}", RNS.LOG_NOTICE)
        else:
            for transient_id, name in unseen.items():
                head = self._read_head(name)
                if head is not None and len(head) < HASH_LENGTH:
                    # Still being written: leave it unseen so the next listing retries it, but
                    # only for a while, or a truncated file would force a listing every poll.
                    first = self._short.setdefault(transient_id, now)
                    if now - first < SHORT_GRACE:
                        incomplete = True
                        continue
                self._short.pop(transient_id, None)
                self._seen[transient_id] = now
                if head is not None and len(head) == HASH_LENGTH and self.registry.get(head) is not None:
                    RNS.log(f"Message arrived for {RNS.prettyhexrep(head)}", RNS.LOG_VERBOSE)
                    self.on_arrival(head)
                    arrivals += 1
            stale = [t for t, at in self._seen.items() if t not in listed and now - at >= self.seen_ttl]
            for transient_id in stale:
                del self._seen[transient_id]
            for transient_id in [t for t in self._short if t not in listed]:
                del self._short[transient_id]
        # Taken before the listing, so a file added during it is seen on the next pass. Not
        # cached while too recent: a file landing in the same mtime tick would leave it unchanged.
        age = self.wall_clock() - mtime_ns / 1e9
        recent = 0 <= age < max(2.0, self.interval)
        self._dir_mtime_ns = None if recent or incomplete else mtime_ns
        return arrivals

    def _read_head(self, name):
        """The file's first bytes, or None if it vanished or cannot be read."""
        try:
            with open(os.path.join(self.path, name), "rb") as f:
                return f.read(HASH_LENGTH)
        except OSError:
            return None

    def _fail(self, error):
        if not self._unavailable:
            self._unavailable = True
            RNS.log(f"Message store {self.path} is unavailable: {error}", RNS.LOG_WARNING)

    def _loop(self):
        while not self._stopped.is_set():
            try:
                self.poll()
            except Exception as e:
                RNS.log(f"Message store poll failed: {e}", RNS.LOG_ERROR)
            self._stopped.wait(self.interval)
