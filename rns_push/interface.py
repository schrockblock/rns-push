import collections
import dataclasses
import os
import socket
import threading
import time

import RNS
from RNS.Interfaces.Interface import Interface
from RNS.Interfaces.TCPInterface import TCPClientInterface, TCPServerInterface
from RNS.Transport import IDX_RT_OUTB_IF

from .apns import APNsClient, JWTSigner
from .dispatcher import PushDispatcher
from .packet import parse_header
from .registry import DEFAULT_ASPECTS, Registry
from .service import DEFAULT_MAX_REGISTRATIONS, RegistrationService, load_or_create_identity
from .store_watch import MessageStoreWatcher

PUSHABLE_TYPES = (RNS.Packet.DATA, RNS.Packet.LINKREQUEST)
DIRECT_LINK_CAP = 64


class PushClientInterface(TCPClientInterface):
    """A spawned hub connection. Once bound to a registration, it survives its socket:
    it stays attached to Transport, and what Transport hands it goes out as a push."""

    def __init__(self, owner, configuration, connected_socket=None, *, push_server):
        super().__init__(owner, configuration, connected_socket=connected_socket)
        self.push_server = push_server
        self.bound_hash = None
        self.dormant = False
        self._direct_links = collections.OrderedDict()
        self._direct_links_lock = threading.Lock()

    def is_direct_link(self, link_id):
        """True when the LINKREQUEST for link_id arrived here with wire hops 0, i.e. it was
        sent by the connected peer itself rather than relayed by another transport node."""
        with self._direct_links_lock:
            return link_id in self._direct_links

    def teardown(self):
        # Guarded by the server's bindings_lock for its whole duration (including the unbound
        # branch's super().teardown()): bind()/_release() mutate bound_hash, dormant and online
        # from the server's thread under this same (reentrant) lock, and without it a concurrent
        # bind() could record a binding for an interface that's mid-teardown, or read bound_hash
        # while we're changing it, leaving a zombie dormant-but-unbound interface.
        with self.push_server.bindings_lock:
            if self.bound_hash is None:
                return super().teardown()
            # self.dormant is set first, before anything else, to close the race where a
            # concurrent transmit sees online=False/dormant=False. self.online is explicitly
            # (re)set True, not merely left alone: stock read_loop sets self.online = False
            # immediately before calling teardown() -- both on a clean peer close (TCPInterface.py
            # :416) and on a socket exception (:428) -- and RNS 1.5.5 Transport._inbound() drops
            # every inbound packet whose receiving_interface.online is False (Transport.py:1916),
            # which would make a dormant interface's redirected proofs get discarded before the
            # proof branch ever runs.
            was_dormant = self.dormant
            self.dormant = True
            self.online = True
            if not was_dormant:
                RNS.log(f"{self} is dormant for {RNS.prettyhexrep(self.bound_hash)}", RNS.LOG_INFO)
            if self.socket is not None:
                try:
                    self.socket.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                try:
                    self.socket.close()
                except OSError:
                    pass
                # Dropped so a later detach() (Interface.detach checks "if self.socket != None")
                # doesn't try to shutdown/close an already-closed socket and log EBADF noise.
                self.socket = None

    def retire(self):
        RNS.log(f"Retiring {self}", RNS.LOG_VERBOSE)
        self.dormant = False
        self.bound_hash = None
        self.online = False
        self.OUT = False
        self.IN = False
        parent = self.parent_interface
        if parent is not None:
            while self in parent.spawned_interfaces:
                parent.spawned_interfaces.remove(self)
        RNS.Transport.remove_interface(self)

    def process_outgoing(self, data):
        if not self.dormant:
            return super().process_outgoing(data)
        try:
            header = parse_header(data)
            if header is not None and header.destination_hash == self.bound_hash and header.packet_type in PUSHABLE_TYPES:
                self.push_server.dispatcher.enqueue(header.destination_hash, data,
                                                    silent=header.packet_type == RNS.Packet.LINKREQUEST)
        except Exception as e:
            RNS.log(f"Could not queue a push from {self}: {e}", RNS.LOG_ERROR)

    def process_incoming(self, data):
        self._note_direct_link(data)
        target = self._proof_target(data)
        if target is None:
            return super().process_incoming(data)
        if self.online and not self.detached:
            self.rxb += len(data)
            if self.parent_interface is not None:
                self.parent_interface.rxb += len(data)
            self.owner.inbound(data, target)

    def _note_direct_link(self, data):
        try:
            if len(data) < 2 or data[1] != 0:
                return
            header = parse_header(data)
            if header is None or header.packet_type != RNS.Packet.LINKREQUEST:
                return
            packet = RNS.Packet(None, data)
            packet.unpack()
            link_id = RNS.Link.link_id_from_lr_packet(packet)
            with self._direct_links_lock:
                self._direct_links[link_id] = True
                self._direct_links.move_to_end(link_id)
                while len(self._direct_links) > DIRECT_LINK_CAP:
                    self._direct_links.popitem(last=False)
        except Exception as e:
            RNS.log(f"Could not read a link request on {self}: {e}", RNS.LOG_DEBUG)

    def _proof_target(self, data):
        """Stock Transport forwards a proof only if it arrives on the interface the proved
        packet left through. When that interface is one of our dormant ones, the proof
        arrives on a fresh connection instead, so hand it to Transport as the dormant one's."""
        header = parse_header(data)
        if header is None or header.packet_type != RNS.Packet.PROOF:
            return None
        entry = RNS.Transport.reverse_table.get(header.destination_hash)
        if entry is None:
            return None
        outbound = entry[IDX_RT_OUTB_IF]
        if (isinstance(outbound, PushClientInterface) and outbound is not self and outbound.dormant
                and outbound.push_server is self.push_server):
            return outbound
        return None


IFAC_KEYS = ("networkname", "network_name", "passphrase", "pass_phrase", "ifac_size")
REQUIRED_KEYS = ("apns_key_file", "apns_key_id", "apns_team_id", "allowed_bundle_ids")


def _items(value):
    items = value if isinstance(value, (list, tuple)) else str(value).split(",")
    return tuple(str(item).strip() for item in items if str(item).strip())


@dataclasses.dataclass(frozen=True)
class PushSettings:
    key_pem: bytes
    key_id: str
    team_id: str
    allowed_bundle_ids: tuple
    max_registrations: int = DEFAULT_MAX_REGISTRATIONS
    allowed_aspects: tuple = (DEFAULT_ASPECTS,)
    alert_titles: tuple = ()
    propagation_store: str | None = None

    @classmethod
    def from_config(cls, c):
        for key in IFAC_KEYS:
            if key in c:
                raise ValueError(f"PushTCPServerInterface does not support IFAC; remove \"{key}\" from its configuration")
        for key in REQUIRED_KEYS:
            if key not in c or not _items(c[key]):
                raise ValueError(f"PushTCPServerInterface needs \"{key}\" in its configuration")
        key_path = os.path.expanduser(str(c["apns_key_file"]).strip())
        try:
            with open(key_path, "rb") as f:
                key_pem = f.read()
        except OSError as e:
            raise ValueError(f"Cannot read apns_key_file {key_path}: {e}")
        key_id = str(c["apns_key_id"]).strip()
        team_id = str(c["apns_team_id"]).strip()
        JWTSigner(key_pem, key_id, team_id)  # fail at startup, not at the first push
        max_registrations = DEFAULT_MAX_REGISTRATIONS
        if "max_registrations" in c:
            try:
                max_registrations = int(str(c["max_registrations"]).strip())
            except ValueError:
                max_registrations = 0
            if max_registrations < 1:
                raise ValueError(f"PushTCPServerInterface needs a positive integer for \"max_registrations\", "
                                 f"not {c['max_registrations']!r}")
        allowed_aspects = (DEFAULT_ASPECTS,)
        if "push_aspects" in c:
            parsed = []
            for item in _items(c["push_aspects"]):
                parts = tuple(item.split("."))
                if len(parts) < 2 or any(not p for p in parts):
                    raise ValueError(f"PushTCPServerInterface: invalid push_aspects entry {item!r}")
                parsed.append(parts)
            allowed_aspects = tuple(parsed)
        alert_titles = ()
        if "alert_titles" in c:
            pairs = []
            for item in _items(c["alert_titles"]):
                bundle, sep, title = item.partition("=")
                if not sep or not bundle.strip() or not title.strip():
                    raise ValueError(f"PushTCPServerInterface: invalid alert_titles entry {item!r}")
                pairs.append((bundle.strip(), title.strip()))
            alert_titles = tuple(pairs)
        propagation_store = None
        if "propagation_store" in c and str(c["propagation_store"]).strip():
            propagation_store = os.path.expanduser(str(c["propagation_store"]).strip())
        return cls(key_pem, key_id, team_id, _items(c["allowed_bundle_ids"]), max_registrations,
                   allowed_aspects, alert_titles, propagation_store)


def make_apns_client(key_pem, key_id, team_id):
    return APNsClient(JWTSigner(key_pem, key_id, team_id))


class PushTCPServerInterface(TCPServerInterface):
    """A TCPServerInterface whose clients can be woken by APNs while their socket is down."""

    START_SERVICE = True

    def __init__(self, owner, configuration):
        settings = PushSettings.from_config(Interface.get_config_obj(configuration))
        if not RNS.Reticulum.transport_enabled():
            raise ValueError("PushTCPServerInterface requires enable_transport = yes in the [reticulum] section")
        super().__init__(owner, configuration)
        self.settings = settings
        self.storage_dir = os.path.join(RNS.Reticulum.storagepath, "rns_push")
        self.bindings = {}
        self.bindings_lock = threading.RLock()
        self.registry = Registry(os.path.join(self.storage_dir, "registrations.json"))
        self.apns = make_apns_client(settings.key_pem, settings.key_id, settings.team_id)
        self.dispatcher = PushDispatcher(self.registry, self.apns, self.on_unregistered,
                                         titles=dict(settings.alert_titles))
        self.service = RegistrationService(self, self.registry, settings.allowed_bundle_ids,
                                           max_registrations=settings.max_registrations,
                                           allowed_aspects=settings.allowed_aspects)
        self.store_watcher = None
        if settings.propagation_store is not None:
            self.store_watcher = MessageStoreWatcher(settings.propagation_store, self.registry,
                                                     self.dispatcher.enqueue_propagated)
        if self.START_SERVICE:
            threading.Thread(target=self._start_service, daemon=True).start()

    def _start_service(self):
        while not getattr(RNS.Transport, "ready", False) and not self.detached:
            time.sleep(0.5)
        if self.detached:
            return
        try:
            self.service.start(load_or_create_identity(os.path.join(self.storage_dir, "identity")))
        except Exception as e:
            RNS.log(f"Could not start the push registration service: {e}", RNS.LOG_ERROR)
        if self.store_watcher is not None:
            self.store_watcher.start()

    # Copied from RNS 1.5.5 TCPServerInterface.incoming_connection, constructing
    # PushClientInterface instead of TCPClientInterface. IFAC is refused at startup,
    # so the IFAC key derivation is omitted. tests/test_server_interface.py checks
    # that every attribute the stock method copies is still copied here.
    def incoming_connection(self, handler):
        RNS.log("Accepting incoming TCP connection", RNS.LOG_VERBOSE)
        spawned_configuration = {"name": "Client on "+self.name, "target_host": None, "target_port": None, "i2p_tunneled": self.i2p_tunneled}
        spawned_interface = PushClientInterface(self.owner, spawned_configuration, connected_socket=handler.request, push_server=self)
        spawned_interface.OUT = self.OUT
        spawned_interface.IN  = self.IN

        spawned_interface.ingress_control = self.ingress_control
        spawned_interface.ic_max_held_announces = self.ic_max_held_announces
        spawned_interface.ic_burst_hold = self.ic_burst_hold
        spawned_interface.ic_burst_freq = self.ic_burst_freq
        spawned_interface.ic_burst_freq_new = self.ic_burst_freq_new
        spawned_interface.ic_new_time = self.ic_new_time
        spawned_interface.ic_burst_penalty = self.ic_burst_penalty
        spawned_interface.ic_held_release_interval = self.ic_held_release_interval

        spawned_interface.egress_control = self.egress_control
        spawned_interface.ec_pr_freq = self.ec_pr_freq
        spawned_interface.ic_pr_burst_freq_new = self.ic_pr_burst_freq_new
        spawned_interface.ic_pr_burst_freq = self.ic_pr_burst_freq

        spawned_interface.target_ip = handler.client_address[0]
        spawned_interface.target_port = str(handler.client_address[1])
        spawned_interface.parent_interface = self
        spawned_interface.bitrate = self.bitrate
        spawned_interface.optimise_mtu()

        spawned_interface.ifac_size = self.ifac_size
        spawned_interface.ifac_netname = self.ifac_netname
        spawned_interface.ifac_netkey = self.ifac_netkey

        spawned_interface.announce_rate_target = self.announce_rate_target
        spawned_interface.announce_rate_grace = self.announce_rate_grace
        spawned_interface.announce_rate_penalty = self.announce_rate_penalty
        spawned_interface.mode = self.mode
        spawned_interface.gravity = self.gravity
        spawned_interface.recursive_prs = self.recursive_prs
        spawned_interface.announces_from_internal = self.announces_from_internal
        spawned_interface.announces_to_internal = self.announces_to_internal
        spawned_interface.announce_cap = self.announce_cap
        spawned_interface.HW_MTU = self.HW_MTU
        spawned_interface.online = True
        RNS.log("Spawned new push client interface: "+str(spawned_interface), RNS.LOG_VERBOSE)
        RNS.Transport.add_interface(spawned_interface)
        while spawned_interface in self.spawned_interfaces:
            self.spawned_interfaces.remove(spawned_interface)
        self.spawned_interfaces.append(spawned_interface)
        spawned_interface.read_loop()

    def owns(self, interface):
        return isinstance(interface, PushClientInterface) and interface.push_server is self

    def bind(self, destination_hash, interface):
        with self.bindings_lock:
            if not interface.IN:
                return
            previous = self.bindings.get(destination_hash)
            if previous is interface:
                return
            if previous is not None:
                self._release(previous)
            if interface.bound_hash is not None and interface.bound_hash != destination_hash:
                self.bindings.pop(interface.bound_hash, None)
            interface.bound_hash = destination_hash
            self.bindings[destination_hash] = interface
        RNS.log(f"Bound {RNS.prettyhexrep(destination_hash)} to {interface}", RNS.LOG_VERBOSE)

    def retire(self, destination_hash):
        with self.bindings_lock:
            interface = self.bindings.pop(destination_hash, None)
            if interface is not None:
                self._release(interface)

    def on_unregistered(self, registration):
        """APNs rejected the token of this registration. The client may have re-registered
        with a new token since the push was sent, so only that exact token is dropped."""
        if self.registry.remove_if_token(registration.destination_hash, registration.token):
            self.retire(registration.destination_hash)

    def _release(self, interface):
        if interface.dormant:
            interface.retire()
        else:
            interface.bound_hash = None

    def detach(self):
        super().detach()
        if self.store_watcher is not None:
            self.store_watcher.stop()
        self.dispatcher.stop()
        self.service.stop()
        self.apns.close()
