import collections
import os
import threading
import time

import RNS
from RNS.Transport import IDX_PT_HOPS, IDX_PT_RVCD_IF
from RNS.vendor import umsgpack

from .registry import ENVIRONMENTS, Registration, delivery_hash

APP_NAME = "rnspush"
ASPECT = "registration"
ANNOUNCE_INTERVAL = 30 * 60
SWEEP_INTERVAL = 60 * 60
REQUEST_LIMIT = 10
REQUEST_WINDOW = 60 * 60
MAX_TOKEN_LENGTH = 100
DEFAULT_MAX_REGISTRATIONS = 10000


def _error(code):
    return {"ok": False, "error": code}


def find_active_link(link_id):
    for link in list(RNS.Transport.active_links):
        if link.link_id == link_id:
            return link
    return None


def path_interface(destination_hash):
    """(receiving interface, hop count) of the current path, or (None, None)."""
    entry = RNS.Transport.path_table.get(destination_hash)
    if entry is None:
        return None, None
    return entry[IDX_PT_RVCD_IF], entry[IDX_PT_HOPS]


def load_or_create_identity(path):
    if os.path.isfile(path):
        identity = RNS.Identity.from_file(path)
        if identity is None:
            raise ValueError(f"Could not load the push hub identity from {path}")
        return identity
    os.makedirs(os.path.dirname(path), exist_ok=True)
    identity = RNS.Identity()
    identity.to_file(path)
    return identity


class _BadRequest(Exception):
    pass


class RegistrationService:
    """The rnspush.registration destination: /register and /unregister over an identified
    link, plus an lxmf.delivery announce handler that re-binds reconnecting clients."""

    aspect_filter = "lxmf.delivery"

    def __init__(self, server, registry, allowed_bundle_ids, max_registrations=DEFAULT_MAX_REGISTRATIONS,
                 clock=time.time, find_link=find_active_link, path_interface=path_interface):
        self.server = server
        self.registry = registry
        self.allowed_bundle_ids = frozenset(allowed_bundle_ids)
        self.max_registrations = max_registrations
        self.clock = clock
        self.find_link = find_link
        self.path_interface = path_interface
        self.destination = None
        self._requests = collections.defaultdict(collections.deque)
        self._lock = threading.Lock()
        self._stopped = threading.Event()

    def start(self, identity):
        destination = RNS.Destination(identity, RNS.Destination.IN, RNS.Destination.SINGLE, APP_NAME, ASPECT)
        destination.register_request_handler("/register", response_generator=self.handle_register,
                                             allow=RNS.Destination.ALLOW_ALL)
        destination.register_request_handler("/unregister", response_generator=self.handle_unregister,
                                             allow=RNS.Destination.ALLOW_ALL)
        self.destination = destination
        RNS.Transport.register_announce_handler(self)
        RNS.log(f"Push registration destination is {RNS.prettyhexrep(destination.hash)}", RNS.LOG_NOTICE)
        threading.Thread(target=self._maintenance_loop, daemon=True).start()

    def stop(self):
        self._stopped.set()
        try:
            RNS.Transport.deregister_announce_handler(self)
        except Exception as e:
            RNS.log(f"Could not deregister the push announce handler: {e}", RNS.LOG_ERROR)
        if self.destination is not None:
            try:
                RNS.Transport.deregister_destination(self.destination)
            except Exception as e:
                RNS.log(f"Could not deregister the push registration destination: {e}", RNS.LOG_ERROR)
            self.destination = None

    def announce(self):
        self.destination.announce(app_data=umsgpack.packb({"v": 1}))

    def sweep(self):
        for destination_hash in self.registry.expire():
            self.server.retire(destination_hash)
        now = self.clock()
        with self._lock:
            stale = [identity_hash for identity_hash, history in self._requests.items()
                     if not history or now - history[-1] >= REQUEST_WINDOW]
            for identity_hash in stale:
                del self._requests[identity_hash]

    def handle_register(self, path, data, request_id, link_id, remote_identity, requested_at):
        try:
            interface, error = self._preflight(link_id, remote_identity)
            if error is not None:
                return error
            token, environment, bundle_id = self._parse_register(data)
            if bundle_id not in self.allowed_bundle_ids:
                return _error("bundle_not_allowed")
            destination_hash = delivery_hash(remote_identity)
            if self.registry.get(destination_hash) is None and len(self.registry.all()) >= self.max_registrations:
                RNS.log(f"Push registry is full ({self.max_registrations}), refusing a new registration", RNS.LOG_WARNING)
                return _error("rate_limited")
            registration = Registration(destination_hash, remote_identity.get_public_key(), token,
                                        environment, bundle_id, self.clock())
            self.registry.put(registration)
            self.server.bind(destination_hash, interface)
            RNS.log(f"Registered {RNS.prettyhexrep(destination_hash)} for push", RNS.LOG_INFO)
            return {"ok": True, "destination_hash": destination_hash, "expires_at": int(registration.expires_at)}
        except _BadRequest:
            return _error("bad_request")
        except Exception as e:
            RNS.log(f"Push /register failed: {e}", RNS.LOG_ERROR)
            return _error("bad_request")

    def handle_unregister(self, path, data, request_id, link_id, remote_identity, requested_at):
        try:
            _, error = self._preflight(link_id, remote_identity)
            if error is not None:
                return error
            if not isinstance(data, dict) or data.get("v") != 1:
                return _error("bad_request")
            destination_hash = delivery_hash(remote_identity)
            self.registry.remove(destination_hash)
            self.server.retire(destination_hash)
            return {"ok": True}
        except Exception as e:
            RNS.log(f"Push /unregister failed: {e}", RNS.LOG_ERROR)
            return _error("bad_request")

    def received_announce(self, destination_hash, announced_identity, app_data):
        try:
            registration = self.registry.get(destination_hash)
            if registration is None or announced_identity is None:
                return
            if announced_identity.get_public_key() != registration.identity_public_key:
                return
            # Hops 1 means the announcing node is our direct neighbour on that interface. Anything
            # further away was relayed by another transport node connected to us, whose
            # interface must never be bound (it would black-hole every path learned via it).
            interface, hops = self.path_interface(destination_hash)
            if hops == 1 and self.server.owns(interface):
                self.server.bind(destination_hash, interface)
        except Exception as e:
            RNS.log(f"Push announce handler failed: {e}", RNS.LOG_ERROR)

    def _preflight(self, link_id, remote_identity):
        if remote_identity is None:
            return None, _error("not_identified")
        if not self._admit(remote_identity.hash):
            return None, _error("rate_limited")
        link = self.find_link(link_id)
        interface = getattr(link, "attached_interface", None) if link is not None else None
        if not (self.server.owns(interface) and interface.is_direct_link(link_id)):
            return None, _error("not_direct")
        return interface, None

    def _parse_register(self, data):
        if not isinstance(data, dict) or data.get("v") != 1:
            raise _BadRequest()
        token = data.get("token")
        environment = data.get("environment")
        bundle_id = data.get("bundle_id")
        if not isinstance(token, bytes) or not 1 <= len(token) <= MAX_TOKEN_LENGTH:
            raise _BadRequest()
        if not isinstance(environment, str) or environment not in ENVIRONMENTS:
            raise _BadRequest()
        if not isinstance(bundle_id, str) or not bundle_id:
            raise _BadRequest()
        return token, environment, bundle_id

    def _admit(self, identity_hash):
        now = self.clock()
        with self._lock:
            history = self._requests[identity_hash]
            while history and now - history[0] >= REQUEST_WINDOW:
                history.popleft()
            if len(history) >= REQUEST_LIMIT:
                return False
            history.append(now)
            return True

    def _maintenance_loop(self):
        last_announce = None
        last_sweep = time.monotonic()
        while not self._stopped.is_set():
            now = time.monotonic()
            if last_announce is None or now - last_announce >= ANNOUNCE_INTERVAL:
                try:
                    self.announce()
                except Exception as e:
                    RNS.log(f"Could not announce the push registration destination: {e}", RNS.LOG_ERROR)
                last_announce = now
            if now - last_sweep >= SWEEP_INTERVAL:
                try:
                    self.sweep()
                except Exception as e:
                    RNS.log(f"Push registration sweep failed: {e}", RNS.LOG_ERROR)
                last_sweep = now
            self._stopped.wait(10)
