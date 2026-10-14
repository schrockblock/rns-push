import base64
import collections
import json
import threading
import time

import RNS

WINDOW = 0.5
MAX_PACKETS = 8
MAX_B64 = 3500
RATE_LIMIT = 20
RATE_WINDOW = 60.0
QUEUE_CAP = 1024
RETRY_DELAY = 1.0
PUSH_TITLE = "New message"
UNREGISTERED_REASONS = ("BadDeviceToken", "DeviceTokenNotForTopic")


def build_payload(packets_b64, title=PUSH_TITLE):
    return json.dumps({"aps": {"alert": {"title": title},"mutable-content": 1, "content-available": 1},
                       "rns": {"v": 1, "packets": list(packets_b64)}},
                      separators=(",", ":")).encode("utf-8")


class _Batch:
    def __init__(self, opened):
        self.opened = opened
        self.packets = []
        self.size = 0


class PushDispatcher:
    """Turns packets handed to dormant interfaces into APNs pushes. enqueue() never blocks;
    a single worker thread batches, rate-limits and sends."""

    def __init__(self, registry, apns, on_unregistered, clock=time.monotonic, sleep=time.sleep, start_thread=True,
                 titles=None):
        self.titles = dict(titles or {})
        self.registry = registry
        self.apns = apns
        self.on_unregistered = on_unregistered
        self.clock = clock
        self.sleep = sleep
        self._queue = collections.deque()
        self._lock = threading.Lock()
        self._wake = threading.Event()
        self._stopped = False
        self._batches = {}
        self._history = collections.defaultdict(collections.deque)
        if start_thread:
            threading.Thread(target=self._run, daemon=True).start()

    def enqueue(self, destination_hash, raw):
        with self._lock:
            if len(self._queue) >= QUEUE_CAP:
                self._queue.popleft()
                RNS.log("Push queue is full, dropping the oldest packet", RNS.LOG_WARNING)
            self._queue.append((destination_hash, raw))
        self._wake.set()

    def step(self):
        """Move queued packets into batches and flush the ones that are due.
        Returns the seconds until the next batch is due, or None when nothing is pending."""
        with self._lock:
            items = list(self._queue)
            self._queue.clear()
        for destination_hash, raw in items:
            self._add(destination_hash, raw)
        now = self.clock()
        for destination_hash in [h for h, b in self._batches.items() if now - b.opened >= WINDOW]:
            self._flush(destination_hash)
        if not self._batches:
            return None
        return max(0.0, min(b.opened for b in self._batches.values()) + WINDOW - self.clock())

    def stop(self):
        self._stopped = True
        self._wake.set()

    def _run(self):
        timeout = None
        while not self._stopped:
            self._wake.wait(timeout)
            self._wake.clear()
            if self._stopped:
                break
            try:
                timeout = self.step()
            except Exception as e:
                RNS.log(f"Push dispatcher error: {e}", RNS.LOG_ERROR)
                timeout = WINDOW

    def _add(self, destination_hash, raw):
        entry = base64.b64encode(raw).decode("ascii")
        batch = self._batches.get(destination_hash)
        if batch is not None and batch.size + len(entry) > MAX_B64:
            self._flush(destination_hash)
            batch = None
        if batch is None:
            batch = _Batch(self.clock())
            self._batches[destination_hash] = batch
        batch.packets.append(entry)
        batch.size += len(entry)
        if len(batch.packets) >= MAX_PACKETS:
            self._flush(destination_hash)

    def _flush(self, destination_hash):
        batch = self._batches.pop(destination_hash)
        registration = self.registry.get(destination_hash)
        if registration is None:
            RNS.log(f"Dropping push for unregistered {RNS.prettyhexrep(destination_hash)}", RNS.LOG_DEBUG)
            return
        now = self.clock()
        history = self._history[destination_hash]
        while history and now - history[0] >= RATE_WINDOW:
            history.popleft()
        if len(history) >= RATE_LIMIT:
            RNS.log(f"Push rate limit reached for {RNS.prettyhexrep(destination_hash)}, dropping", RNS.LOG_DEBUG)
            return
        history.append(now)
        self._send(registration, build_payload(batch.packets, self.titles.get(registration.bundle_id, PUSH_TITLE)))

    def _send(self, registration, payload):
        arguments = (registration.environment, registration.token.hex(), registration.bundle_id,
                     registration.destination_hash.hex(), payload)
        status, reason = self.apns.send(*arguments)
        if status == 0 or status == 429 or status >= 500:
            self.sleep(RETRY_DELAY)
            status, reason = self.apns.send(*arguments)
        elif status == 403 and reason == "ExpiredProviderToken":
            self.apns.invalidate_token()
            status, reason = self.apns.send(*arguments)
        if status == 200:
            return
        if status == 410 or (status == 400 and reason in UNREGISTERED_REASONS):
            RNS.log(f"APNs rejected the token for {RNS.prettyhexrep(registration.destination_hash)} ({status} {reason}), unregistering", RNS.LOG_NOTICE)
            self.on_unregistered(registration)
            return
        RNS.log(f"APNs push for {RNS.prettyhexrep(registration.destination_hash)} failed: {status} {reason}", RNS.LOG_ERROR)
