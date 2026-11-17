import collections
import contextlib
import dataclasses
import os
import socket
import sys
import threading
import time
import weakref

import RNS
from RNS.Interfaces.Interface import Interface
from RNS.Interfaces.TCPInterface import TCPClientInterface, TCPServerInterface
from RNS.Transport import IDX_LT_DSTHASH, IDX_LT_NH_IF, IDX_RT_OUTB_IF

from .apns import APNsClient, JWTSigner
from .dispatcher import PushDispatcher
from .packet import parse_header
from .registry import DEFAULT_ASPECTS, Registry
from .service import DEFAULT_MAX_REGISTRATIONS, RegistrationService, load_or_create_identity
from .store_watch import MessageStoreWatcher

PUSHABLE_TYPES = (RNS.Packet.DATA, RNS.Packet.LINKREQUEST)
DIRECT_LINK_CAP = 64
STANDBY_PORT = "push"
TRANSPORT_WAIT = 120.0
TRANSPORT_POLL = 0.1
RANDOM_BLOB_LENGTH = 10
PATH_TIMEOUT_FALLBACK = 60 * 60 * 24 * 7


def _path_table_indexes():
    """{name: index} of the IDX_PT_* path table field constants of the installed RNS.
    RNS.Transport is the class; the constants live on the module behind it."""
    module = sys.modules.get("RNS.Transport")
    return {name: getattr(module, name) for name in dir(module) if name.startswith("IDX_PT_")}


def _path_table_lock():
    # RNS 1.5.5 has no path_table_lock.
    return getattr(RNS.Transport, "path_table_lock", None) or contextlib.nullcontext()


def _path_timeout(interface):
    if hasattr(RNS.Transport, "path_timeout_from_interface"):
        return RNS.Transport.path_timeout_from_interface(interface)
    return getattr(RNS.Transport, "PATHFINDER_E", PATH_TIMEOUT_FALLBACK)


def standing_random_blob(now):
    """A path table random blob whose emission time is `now`: an announce for the destination
    replaces the entry only if it was emitted later, which a reconnecting client's is, and a
    stale copy replayed from another node's cache is not."""
    return os.urandom(RANDOM_BLOB_LENGTH - 5) + int(now).to_bytes(5, "big")


def last_announce_hash(destination_hash):
    """The packet hash of the last announce RNS remembered for destination_hash, so a standing
    path still answers path requests from the announce cache; all zeros when none is known."""
    known = getattr(RNS.Identity, "known_destinations", None)
    lock = getattr(RNS.Identity, "known_destinations_lock", None) or contextlib.nullcontext()
    with lock:
        entry = known.get(destination_hash) if isinstance(known, dict) else None
    width = RNS.Identity.HASHLENGTH // 8
    if entry is not None and len(entry) > 1 and isinstance(entry[1], (bytes, bytearray)) and len(entry[1]) == width:
        return bytes(entry[1])
    return bytes(width)


_servers = weakref.WeakSet()


def watch_interface_removals():
    """Wrap RNS.Transport.remove_interface so that whatever interface leaves Transport, every
    bound destination whose path ran through it is pointed back at its bound interface before
    Transport's next table cull can drop the path along with the interface.

    rns-push's own unbound connections already do this from teardown(); this catches the rest.
    Seen live: a phone on the hub's LAN announces over multicast while its app is open, so
    Transport moves its path onto the AutoInterfacePeer the hub spawns for it; ~22 s after the
    app closes the peer times out, the interface is removed, and the cull removes the path.
    The bound dormant TCP interface is still there, but with no path nothing is pushed."""
    current = RNS.Transport.remove_interface
    if getattr(current, "_rns_push_restores", False):
        return
    stock = current

    def remove_interface(interface):
        try:
            return stock(interface)
        finally:
            for server in list(_servers):
                try:
                    server.restore_paths_through(interface)
                except Exception as e:
                    RNS.log(f"Could not restore push paths after {interface} was removed: {e}", RNS.LOG_ERROR)

    remove_interface._rns_push_restores = True
    RNS.Transport.remove_interface = staticmethod(remove_interface)


def ensure_push_path(destination_hash, interface, now=None):
    """Make the hub's path to destination_hash the one-hop path through interface, which is what
    a bound push client's path always is, and keep that path from expiring.

    Transport only hands a packet to an interface it has a path table entry for, and the push
    machinery hangs off that: no entry, no push, the packet is dropped as "no known path". A
    bound client's entry goes missing after an rnsd restart (dormant interfaces do not survive
    one, so the saved entry is discarded), when the client's reconnect announce was lost (rnsd
    drops every packet until its transport identity has loaded, well after it accepts TCP
    clients), after a week without an announce, or when a stale announce for the client relayed
    from the wider network has pointed the path elsewhere. This creates the entry when there is
    none, redirects one that points at another interface, and only refreshes one that already
    points here (the expiry, and RNS 1.6.0's "last used" field, which that version culls on
    1.75 h after learning a path no packet ever used). Returns True when the entry was created
    or redirected."""
    now = time.time() if now is None else now
    idx = _path_table_indexes()
    expires = now + _path_timeout(interface)
    with _path_table_lock():
        table = RNS.Transport.path_table
        entry = table.get(destination_hash)
        if entry is not None and entry[idx["IDX_PT_RVCD_IF"]] is interface:
            if entry[idx["IDX_PT_EXPIRES"]] < expires:
                entry[idx["IDX_PT_EXPIRES"]] = expires
            used = idx.get("IDX_PT_USED")
            if used is not None and len(entry) > used and not entry[used]:
                entry[used] = now
            return False
        fields = {idx["IDX_PT_TIMESTAMP"]: now,
                  idx["IDX_PT_NEXT_HOP"]: destination_hash,
                  idx["IDX_PT_HOPS"]: 1,
                  idx["IDX_PT_EXPIRES"]: expires,
                  idx["IDX_PT_RANDBLOBS"]: [standing_random_blob(now)],
                  idx["IDX_PT_RVCD_IF"]: interface,
                  idx["IDX_PT_PACKET"]: last_announce_hash(destination_hash)}
        if "IDX_PT_USED" in idx:
            fields[idx["IDX_PT_USED"]] = now
        table[destination_hash] = [fields.get(i) for i in range(max(idx.values()) + 1)]
        return True


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
                super().teardown()
            else:
                self._go_dormant()
                return
        # Outside bindings_lock, since this takes Transport.path_table_lock (see bind()).
        self.push_server.restore_paths_through(self)

    def _go_dormant(self):
        """The bound branch of teardown(), under the server's bindings_lock."""
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
        self._adopt_link(data)
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

    def _adopt_link(self, data):
        """A link-request proof answers a LINKREQUEST that left through one of this hub's push
        interfaces as a push: the phone woke and is answering on this connection, usually before
        the announce that will rebind it has been handled (Transport runs announce handlers on
        their own threads). Transport forwards a link proof only when it arrives on the link's
        next-hop interface, and routes the link's packets there, so the link is handed to this
        connection first. Transport still validates the proof's signature before forwarding."""
        try:
            header = parse_header(data)
            if header is None or header.packet_type != RNS.Packet.PROOF or header.context != RNS.Packet.LRPROOF:
                return
            with RNS.Transport.link_table_lock:
                entry = RNS.Transport.link_table.get(header.destination_hash)
                if entry is None:
                    return
                through = entry[IDX_LT_NH_IF]
                if through is self or not isinstance(through, PushClientInterface) or through.push_server is not self.push_server:
                    return
                entry[IDX_LT_NH_IF] = self
                destination_hash = entry[IDX_LT_DSTHASH]
            RNS.log(f"Link {RNS.prettyhexrep(header.destination_hash)} to {RNS.prettyhexrep(destination_hash)} now runs "
                    f"over {self}; its request went out through {through}", RNS.LOG_VERBOSE)
        except Exception as e:
            RNS.log(f"Could not adopt a link proof on {self}: {e}", RNS.LOG_DEBUG)

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
        _servers.add(self)
        watch_interface_removals()
        if self.START_SERVICE:
            threading.Thread(target=self._start_service, daemon=True).start()

    def _start_service(self):
        while not getattr(RNS.Transport, "ready", False) and not self.detached:
            time.sleep(0.5)
        if self.detached:
            return
        # Before the service: a registered client's packets must have somewhere to go from the
        # moment Transport is up, whether or not the client ever reconnects and announces.
        try:
            self.ensure_standbys()
        except Exception as e:
            RNS.log(f"Could not stand in for the registered push clients: {e}", RNS.LOG_ERROR)
        try:
            self.service.start(load_or_create_identity(os.path.join(self.storage_dir, "identity")))
        except Exception as e:
            RNS.log(f"Could not start the push registration service: {e}", RNS.LOG_ERROR)
        # Detaching while the service started would otherwise leave a watcher nobody stops.
        if self.detached:
            return
        if self.store_watcher is not None:
            self.store_watcher.start()

    # Copied from RNS 1.5.5 TCPServerInterface.incoming_connection, constructing
    # PushClientInterface instead of TCPClientInterface. IFAC is refused at startup,
    # so the IFAC key derivation is omitted. tests/test_server_interface.py checks
    # that every attribute the stock method copies is still copied here, on every
    # RNS version the package supports.
    def incoming_connection(self, handler):
        RNS.log("Accepting incoming TCP connection", RNS.LOG_VERBOSE)
        self._wait_for_transport()
        spawned_configuration = {"name": "Client on "+self.name, "target_host": None, "target_port": None, "i2p_tunneled": self.i2p_tunneled}
        spawned_interface = PushClientInterface(self.owner, spawned_configuration, connected_socket=handler.request, push_server=self)
        self._adopt(spawned_interface, handler.client_address[0], str(handler.client_address[1]))
        spawned_interface.online = True
        RNS.log("Spawned new push client interface: "+str(spawned_interface), RNS.LOG_VERBOSE)
        RNS.Transport.add_interface(spawned_interface)
        while spawned_interface in self.spawned_interfaces:
            self.spawned_interfaces.remove(spawned_interface)
        self.spawned_interfaces.append(spawned_interface)
        spawned_interface.read_loop()

    def _wait_for_transport(self):
        """rnsd accepts TCP clients as soon as its config is read, but Transport drops every packet
        until its identity and tables have loaded, up to a minute later on a slow hub, so a client
        that reconnects during startup announces into the void and stays unbound until its next
        launch. Hold the connection's reader until Transport is ready: the client's announce waits
        in the socket buffer and is read, and binds, the moment Transport can take it."""
        waited = 0.0
        while not getattr(RNS.Transport, "ready", True) and not self.detached and waited < TRANSPORT_WAIT:
            time.sleep(TRANSPORT_POLL)
            waited += TRANSPORT_POLL
        if waited:
            RNS.log(f"Held an incoming connection {waited:.1f}s for transport startup", RNS.LOG_VERBOSE)

    def _adopt(self, spawned_interface, target_ip, target_port):
        """Give a client interface the settings stock TCPServerInterface gives its spawned ones."""
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

        # RNS 1.6.0 added per-interface cost overrides and copies them to spawned
        # interfaces; 1.5.5 has neither attribute, hence getattr.
        spawned_interface._destination_cost = getattr(self, "_destination_cost", None)
        spawned_interface._pr_cost = getattr(self, "_pr_cost", None)

        spawned_interface.target_ip = target_ip
        spawned_interface.target_port = target_port
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

    def owns(self, interface):
        return isinstance(interface, PushClientInterface) and interface.push_server is self

    def standby(self, destination_hash):
        """Bind destination_hash to a push client that never had a socket, so Transport has an
        interface to hand its packets to, and pushes them, while no connection of the client's
        is bound: after an rnsd restart (bindings live in memory), or when the client's
        reconnect announce never reached Transport. It is a dormant interface in every way
        that matters and is retired like one when a real connection binds. Returns the new
        interface, or None when the destination is already bound."""
        with self.bindings_lock:
            if destination_hash in self.bindings:
                return None
            configuration = {"name": "Standby on "+self.name, "target_host": None, "target_port": None,
                             "i2p_tunneled": self.i2p_tunneled}
            interface = PushClientInterface(self.owner, configuration, push_server=self)
            self._adopt(interface, RNS.hexrep(destination_hash, delimit=False), STANDBY_PORT)
            interface.dormant = True
            interface.online = True
            RNS.Transport.add_interface(interface)
            self.spawned_interfaces.append(interface)
            self._bind(destination_hash, interface)
        RNS.log(f"{interface} stands in for {RNS.prettyhexrep(destination_hash)} until it connects", RNS.LOG_INFO)
        ensure_push_path(destination_hash, interface)
        return interface

    def ensure_standbys(self):
        """A standby for every registration nothing is bound to."""
        for registration in self.registry.all():
            self.standby(registration.destination_hash)

    def bind(self, destination_hash, interface):
        with self.bindings_lock:
            if not self._bind(destination_hash, interface):
                return
        # Outside bindings_lock, since this takes Transport.path_table_lock, which Transport may
        # hold while calling into code that takes bindings_lock.
        ensure_push_path(destination_hash, interface)

    def _bind(self, destination_hash, interface):
        if not interface.IN:
            return False
        previous = self.bindings.get(destination_hash)
        if previous is not interface:
            if previous is not None:
                self._release(previous)
            if interface.bound_hash is not None and interface.bound_hash != destination_hash:
                self.bindings.pop(interface.bound_hash, None)
            interface.bound_hash = destination_hash
            self.bindings[destination_hash] = interface
            RNS.log(f"Bound {RNS.prettyhexrep(destination_hash)} to {interface}", RNS.LOG_VERBOSE)
        return True

    def maintain_paths(self):
        """Hourly from the registration service's sweep: every registration is bound to
        something, with a standby if need be, and keeps its one-hop path through it."""
        self.ensure_standbys()
        self.repin_paths()

    def repin_paths(self):
        """Every bound destination's path is the one-hop path through its bound interface.
        Cheap, so the registration service runs it every maintenance tick: a later-emitted
        announce heard elsewhere (a LAN multicast peer, a relayed copy) moves the path away, and
        packets then go there instead of to the push machinery."""
        with self.bindings_lock:
            bound = list(self.bindings.items())
        for destination_hash, interface in bound:
            ensure_push_path(destination_hash, interface)

    def restore_paths_through(self, interface):
        """An unbound connection is closing. A client that announces over a connection it never
        binds (a push-woken app redials, announces, syncs and hangs up within seconds) moves the
        hub's path to it onto that connection, and Transport's next table cull drops the path
        along with the interface, leaving the client's still-bound dormant interface with no
        path: every direct send to it then fails over to propagation, whose arrival push wakes
        the app into the same redial. Points every bound destination whose path runs through the
        closing interface back at its bound interface. Returns those destinations."""
        received_on = _path_table_indexes()["IDX_PT_RVCD_IF"]
        try:
            with _path_table_lock():
                moved = [destination_hash for destination_hash, entry in list(RNS.Transport.path_table.items())
                         if entry[received_on] is interface]
        except RuntimeError:
            # RNS 1.5.5 has no path table lock and the table changed under us; the hourly check
            # catches up.
            return []
        if not moved:
            return []
        with self.bindings_lock:
            restored = [(destination_hash, self.bindings[destination_hash]) for destination_hash in moved
                        if destination_hash in self.bindings and self.bindings[destination_hash] is not interface]
        for destination_hash, bound in restored:
            RNS.log(f"Pointing the path to {RNS.prettyhexrep(destination_hash)} back at {bound}, since {interface} closed",
                    RNS.LOG_VERBOSE)
            ensure_push_path(destination_hash, bound)
        return [destination_hash for destination_hash, _ in restored]

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
        _servers.discard(self)
        if self.store_watcher is not None:
            self.store_watcher.stop()
        self.dispatcher.stop()
        self.service.stop()
        self.apns.close()


# RNS 1.5.5 interface discovery picks what to announce by class name (Discovery.py
# InterfaceAnnouncer.DISCOVERABLE_INTERFACE_TYPES) and silently skips any name it doesn't
# know, so the hub reports the stock name. Reticulum loads it through the shim's
# interface_class, never by name, and __qualname__ keeps reprs pointing here.
PushTCPServerInterface.__name__ = "TCPServerInterface"
