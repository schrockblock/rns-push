import inspect
import os
import re
import shutil
import socket
import tempfile
import time
import unittest
from unittest import mock

import RNS
from RNS import Discovery
from RNS.Interfaces.Interface import Interface
from RNS.vendor import umsgpack
from RNS.Interfaces.TCPInterface import HDLC, TCPServerInterface

import rns_push.interface as push_interface
from rns_push.interface import PushClientInterface, PushSettings, PushTCPServerInterface
from rns_push.registry import Registration
from tests.support import FakeAPNs, ensure_reticulum, make_raw, p256_pem, tcp_pair

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
H1 = b"\x01" * 16
H2 = b"\x02" * 16


def name_to_hash(name):
    """h1 -> H1, h2 -> H2, ..."""
    return bytes([int(name[1:])]) * 16


class StubInterface:
    def __init__(self, dormant=False):
        self.bound_hash = None
        self.dormant = dormant
        self.retired = False
        self.IN = True

    def retire(self):
        self.retired = True
        self.bound_hash = None
        self.dormant = False


def wait_for(condition, timeout=3.0):
    deadline = time.monotonic() + timeout
    while not condition() and time.monotonic() < deadline:
        time.sleep(0.02)
    return condition()


class ServerInterfaceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ensure_reticulum()

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir)
        _, pem = p256_pem()
        self.key_path = os.path.join(self.dir, "AuthKey_TEST.p8")
        with open(self.key_path, "wb") as f:
            f.write(pem)
        self.apns = FakeAPNs()
        for patcher in (mock.patch.object(RNS.Reticulum, "transport_enabled", return_value=True),
                        mock.patch.object(RNS.Reticulum, "storagepath", self.dir),
                        mock.patch.object(push_interface, "make_apns_client", return_value=self.apns),
                        mock.patch.object(PushTCPServerInterface, "START_SERVICE", False)):
            patcher.start()
            self.addCleanup(patcher.stop)

    def config(self, **overrides):
        config = {"name": "Push Hub", "listen_ip": "127.0.0.1", "listen_port": 0,
                  "apns_key_file": self.key_path, "apns_key_id": "KEY123", "apns_team_id": "TEAM456",
                  "allowed_bundle_ids": "co.example.push"}
        config.update(overrides)
        return {k: v for k, v in config.items() if v is not None}

    def make_server(self, **overrides):
        server = PushTCPServerInterface(RNS.Transport, self.config(**overrides))
        self.addCleanup(server.detach)
        # What Reticulum's interface_post_init would set.
        server.OUT = True
        server.ifac_size = None
        server.ifac_netname = None
        server.ifac_netkey = None
        server.announce_rate_target = None
        server.announce_rate_grace = None
        server.announce_rate_penalty = None
        return server

    # configuration

    def test_each_required_key_is_enforced(self):
        for key in ("apns_key_file", "apns_key_id", "apns_team_id", "allowed_bundle_ids"):
            with self.subTest(key=key):
                with self.assertRaisesRegex(ValueError, key):
                    PushTCPServerInterface(RNS.Transport, self.config(**{key: None}))

    def test_unreadable_key_file_is_refused(self):
        with self.assertRaisesRegex(ValueError, "apns_key_file"):
            PushTCPServerInterface(RNS.Transport, self.config(apns_key_file=os.path.join(self.dir, "missing.p8")))

    def test_ifac_options_are_refused(self):
        for key in ("networkname", "network_name", "passphrase", "pass_phrase", "ifac_size"):
            with self.subTest(key=key):
                with self.assertRaisesRegex(ValueError, "IFAC"):
                    PushTCPServerInterface(RNS.Transport, self.config(**{key: "16"}))

    def test_transport_must_be_enabled(self):
        with mock.patch.object(RNS.Reticulum, "transport_enabled", return_value=False):
            with self.assertRaisesRegex(ValueError, "enable_transport"):
                PushTCPServerInterface(RNS.Transport, self.config())

    def test_allowed_bundle_ids_parse_from_every_config_shape(self):
        cases = {"co.a": ("co.a",), "co.a, co.b": ("co.a", "co.b"), " co.a ,": ("co.a",),
                 ("co.a", " co.b"): ("co.a", "co.b")}
        for value, expected in cases.items():
            with self.subTest(value=value):
                config = Interface.get_config_obj(self.config(allowed_bundle_ids=list(value) if isinstance(value, tuple) else value))
                self.assertEqual(PushSettings.from_config(config).allowed_bundle_ids, expected)

    def test_max_registrations_defaults_and_parses(self):
        self.assertEqual(PushSettings.from_config(Interface.get_config_obj(self.config())).max_registrations, 10000)
        config = Interface.get_config_obj(self.config(max_registrations="250"))
        self.assertEqual(PushSettings.from_config(config).max_registrations, 250)

    def test_invalid_max_registrations_is_refused(self):
        for value in ("many", "0", "-5"):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "max_registrations"):
                    PushTCPServerInterface(RNS.Transport, self.config(max_registrations=value))

    def test_max_registrations_reaches_the_registration_service(self):
        server = self.make_server(max_registrations="7")
        self.assertEqual(server.service.max_registrations, 7)

    def settings(self, **overrides):
        return PushSettings.from_config(Interface.get_config_obj(self.config(**overrides)))

    def test_push_aspects_default_and_parse(self):
        self.assertEqual(self.settings().allowed_aspects, (("lxmf", "delivery"),))
        settings = self.settings(push_aspects="lxmf.delivery, nbhd.sync")
        self.assertEqual(settings.allowed_aspects, (("lxmf", "delivery"), ("nbhd", "sync")))

    def test_malformed_push_aspects_are_refused(self):
        for value in ("nbhd", "nbhd..sync", ".sync"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.settings(push_aspects=value)

    def test_alert_titles_parse(self):
        settings = self.settings(alert_titles="co.lithobyte.Nbhd=Neighborhood activity")
        self.assertEqual(dict(settings.alert_titles), {"co.lithobyte.Nbhd": "Neighborhood activity"})
        with self.assertRaises(ValueError):
            self.settings(alert_titles="no-equals-sign")

    def test_aspects_and_titles_reach_service_and_dispatcher(self):
        server = self.make_server(push_aspects="lxmf.delivery, nbhd.sync", alert_titles="co.example.push=Hi")
        self.assertIn(("nbhd", "sync"), server.service.allowed_aspects)
        self.assertEqual(server.dispatcher.titles, {"co.example.push": "Hi"})

    def test_propagation_store_parses(self):
        self.assertIsNone(self.settings().propagation_store)
        settings = self.settings(propagation_store=" /data/lxmd/storage/lxmf/messagestore ")
        self.assertEqual(settings.propagation_store, "/data/lxmd/storage/lxmf/messagestore")

    def start_service(self, server):
        with mock.patch.object(RNS.Transport, "ready", True, create=True), \
                mock.patch.object(server.service, "start"):
            server._start_service()

    def test_watcher_wired_when_configured(self):
        store = os.path.join(self.dir, "messagestore")
        server = self.make_server(propagation_store=store)
        self.assertEqual(server.store_watcher.path, store)
        self.assertIs(server.store_watcher.registry, server.registry)
        self.assertEqual(server.store_watcher.on_arrival, server.dispatcher.enqueue_propagated)
        self.start_service(server)
        thread = server.store_watcher._thread
        self.assertTrue(thread.is_alive())
        server.detach()
        self.assertFalse(thread.is_alive())

    def test_detach_during_start_leaves_no_watcher(self):
        server = self.make_server(propagation_store=os.path.join(self.dir, "messagestore"))
        with mock.patch.object(RNS.Transport, "ready", True, create=True), \
                mock.patch.object(server.service, "start", side_effect=lambda *args: server.detach()):
            server._start_service()
        self.assertTrue(server.detached)
        self.assertIsNone(server.store_watcher._thread)

    def test_no_watcher_without_the_key(self):
        server = self.make_server()
        self.assertIsNone(server.store_watcher)
        self.start_service(server)

    def test_state_lives_under_the_storage_path(self):
        server = self.make_server()
        self.assertEqual(server.registry.path, os.path.join(self.dir, "rns_push", "registrations.json"))
        self.assertIs(server.apns, self.apns)

    # spawning

    def test_incoming_connection_spawns_a_push_client_interface(self):
        server = self.make_server()
        with mock.patch.object(RNS.Transport, "add_interface") as add_interface, \
                mock.patch.object(RNS.Transport, "remove_interface"):
            client = socket.create_connection(("127.0.0.1", server.server.server_address[1]))
            try:
                self.assertTrue(wait_for(lambda: len(server.spawned_interfaces) == 1))
                spawned = server.spawned_interfaces[0]
                self.assertIsInstance(spawned, PushClientInterface)
                self.assertIs(spawned.push_server, server)
                self.assertIs(spawned.parent_interface, server)
                self.assertTrue(spawned.online)
                add_interface.assert_called_once_with(spawned)
            finally:
                client.close()
            self.assertTrue(wait_for(lambda: len(server.spawned_interfaces) == 0))

    def test_incoming_connection_waits_for_transport_to_be_ready(self):
        # rnsd accepts clients before Transport can process packets; a client's announce sent
        # then must wait in the socket buffer, not be read into a Transport that drops it.
        server = self.make_server()
        with mock.patch.object(RNS.Transport, "ready", False, create=True), \
                mock.patch.object(RNS.Transport, "add_interface"), \
                mock.patch.object(RNS.Transport, "remove_interface"):
            client = socket.create_connection(("127.0.0.1", server.server.server_address[1]))
            try:
                client.sendall(bytes([HDLC.FLAG]) + b"\x00\x00" + b"\x09" * 16 + b"\x00early" + bytes([HDLC.FLAG]))
                time.sleep(0.5)
                self.assertEqual(server.spawned_interfaces, [])
                RNS.Transport.ready = True
                self.assertTrue(wait_for(lambda: len(server.spawned_interfaces) == 1))
                spawned = server.spawned_interfaces[0]
                self.assertTrue(wait_for(lambda: spawned.rxb > 0), "the bytes sent before readiness were not read")
            finally:
                client.close()
            self.assertTrue(wait_for(lambda: len(server.spawned_interfaces) == 0))

    def test_incoming_connection_copies_cost_overrides(self):
        # RNS 1.6.0 reads these from the spawned interface; on 1.5.5 they are inert extras.
        server = self.make_server()
        server._destination_cost = 3
        server._pr_cost = 5
        with mock.patch.object(RNS.Transport, "add_interface"), \
                mock.patch.object(RNS.Transport, "remove_interface"):
            client = socket.create_connection(("127.0.0.1", server.server.server_address[1]))
            try:
                self.assertTrue(wait_for(lambda: len(server.spawned_interfaces) == 1))
                spawned = server.spawned_interfaces[0]
                self.assertEqual(spawned._destination_cost, 3)
                self.assertEqual(spawned._pr_cost, 5)
            finally:
                client.close()
            self.assertTrue(wait_for(lambda: len(server.spawned_interfaces) == 0))

    def test_incoming_connection_copies_every_attribute_stock_copies(self):
        def assigned(function):
            return set(re.findall(r"spawned_interface\.(\w+)\s*=(?!=)", inspect.getsource(function)))
        derived_ifac = {"ifac_key", "ifac_identity", "ifac_signature"}
        ours = assigned(PushTCPServerInterface.incoming_connection) | assigned(PushTCPServerInterface._adopt)
        missing = assigned(TCPServerInterface.incoming_connection) - derived_ifac - ours
        self.assertEqual(missing, set())

    # binding

    def test_bind_records_the_binding(self):
        server = self.make_server()
        interface = StubInterface()
        server.bind(H1, interface)
        self.assertEqual(interface.bound_hash, H1)
        self.assertIs(server.bindings[H1], interface)

    def test_bind_refuses_an_interface_with_in_false(self):
        server = self.make_server()
        interface = StubInterface()
        interface.IN = False
        server.bind(H1, interface)
        self.assertIsNone(interface.bound_hash)
        self.assertNotIn(H1, server.bindings)

    def test_rebinding_retires_a_dormant_previous_interface(self):
        server = self.make_server()
        old, new = StubInterface(dormant=True), StubInterface()
        server.bind(H1, old)
        server.bind(H1, new)
        self.assertTrue(old.retired)
        self.assertIs(server.bindings[H1], new)

    def test_rebinding_unbinds_a_live_previous_interface_without_retiring_it(self):
        server = self.make_server()
        old, new = StubInterface(), StubInterface()
        server.bind(H1, old)
        server.bind(H1, new)
        self.assertFalse(old.retired)
        self.assertIsNone(old.bound_hash)
        self.assertEqual(new.bound_hash, H1)

    def test_binding_another_hash_drops_the_interfaces_old_binding(self):
        server = self.make_server()
        interface = StubInterface()
        server.bind(H1, interface)
        server.bind(H2, interface)
        self.assertNotIn(H1, server.bindings)
        self.assertEqual(interface.bound_hash, H2)

    def test_retire_releases_the_binding(self):
        server = self.make_server()
        interface = StubInterface(dormant=True)
        server.bind(H1, interface)
        server.retire(H1)
        server.retire(H2)
        self.assertTrue(interface.retired)
        self.assertNotIn(H1, server.bindings)

    def test_apns_rejection_removes_the_registration_and_retires(self):
        server = self.make_server()
        rejected = Registration(H1, b"\x05" * 64, b"\xaa", "sandbox", "co.example.push", time.time())
        server.registry.put(rejected)
        interface = StubInterface(dormant=True)
        server.bind(H1, interface)
        server.on_unregistered(rejected)
        self.assertIsNone(server.registry.get(H1))
        self.assertTrue(interface.retired)
        self.assertNotIn(H1, server.bindings)

    def test_apns_rejection_of_a_replaced_token_keeps_the_fresh_registration(self):
        server = self.make_server()
        rejected = Registration(H1, b"\x05" * 64, b"\xaa", "sandbox", "co.example.push", time.time())
        fresh = Registration(H1, b"\x05" * 64, b"\xbb", "sandbox", "co.example.push", time.time())
        server.registry.put(fresh)
        interface = StubInterface(dormant=True)
        server.bind(H1, interface)
        server.on_unregistered(rejected)
        self.assertEqual(server.registry.get(H1), fresh)
        self.assertFalse(interface.retired)
        self.assertIs(server.bindings[H1], interface)

    # standing paths: a bound registration always has a one-hop path through its interface

    IDX = push_interface._path_table_indexes()
    HAS_USED = "IDX_PT_USED" in IDX  # RNS 1.6.0; 1.5.5 entries have seven fields

    def path_table(self, **entries):
        """Install a fake path table; each entry is laid out as the installed RNS lays them out."""
        table = {name_to_hash(name): entry for name, entry in entries.items()}
        patcher = mock.patch.object(RNS.Transport, "path_table", table)
        patcher.start()
        self.addCleanup(patcher.stop)
        return table

    def entry(self, interface, hops=1, expires=2000.0, used=0, blobs=()):
        entry = [1000.0, b"\x11" * 16, hops, expires, list(blobs), interface, b"\x22" * 32]
        if self.HAS_USED:
            entry.append(used)
        return entry

    def forget_known_destinations(self, **known):
        patcher = mock.patch.object(RNS.Identity, "known_destinations", {name_to_hash(n): e for n, e in known.items()})
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_path_table_indexes_match_the_installed_rns(self):
        major_minor = tuple(int(part) for part in RNS.__version__.split(".")[:2])
        expected = {"IDX_PT_TIMESTAMP": 0, "IDX_PT_NEXT_HOP": 1, "IDX_PT_HOPS": 2, "IDX_PT_EXPIRES": 3,
                    "IDX_PT_RANDBLOBS": 4, "IDX_PT_RVCD_IF": 5, "IDX_PT_PACKET": 6}
        if major_minor >= (1, 6):
            expected["IDX_PT_USED"] = 7
        self.assertEqual(self.IDX, expected)

    def test_ensure_push_path_creates_a_one_hop_entry_through_the_interface(self):
        table = self.path_table()
        self.forget_known_destinations()
        interface = StubInterface()
        self.assertTrue(push_interface.ensure_push_path(H1, interface, now=5000.0))
        entry = table[H1]
        self.assertEqual(len(entry), len(self.IDX))
        self.assertEqual(entry[:4], [5000.0, H1, 1, 5000.0 + 7 * 24 * 3600])
        self.assertIs(entry[5], interface)
        self.assertEqual(entry[6], bytes(32))
        if self.HAS_USED:
            self.assertEqual(entry[7], 5000.0)
        (blob,) = entry[4]
        self.assertEqual(len(blob), 10)
        self.assertEqual(int.from_bytes(blob[5:], "big"), 5000)

    def test_ensure_push_path_references_the_last_announce_rns_remembers(self):
        # So a path request for the client is answered from the announce cache, as for any path.
        table = self.path_table()
        self.forget_known_destinations(h1=[1000.0, b"\x33" * 32, b"key", None, 0])
        push_interface.ensure_push_path(H1, StubInterface())
        self.assertEqual(table[H1][6], b"\x33" * 32)

    def test_ensure_push_path_redirects_an_entry_that_points_elsewhere(self):
        # A stale announce for the client, replayed from across the network, has put the path
        # 32 hops away; the client is bound here, one hop away.
        elsewhere = StubInterface()
        table = self.path_table(h1=self.entry(elsewhere, hops=32, blobs=[b"\x44" * 10]))
        self.forget_known_destinations()
        interface = StubInterface()
        self.assertTrue(push_interface.ensure_push_path(H1, interface, now=5000.0))
        self.assertIs(table[H1][5], interface)
        self.assertEqual(table[H1][2], 1)
        self.assertNotIn(b"\x44" * 10, table[H1][4])

    def test_ensure_push_path_only_refreshes_an_entry_already_through_the_interface(self):
        # The entry Transport built from the client's own announce keeps its random blobs and
        # announce hash, which is how Transport tells a newer announce from a replayed one.
        interface = StubInterface()
        original = self.entry(interface, blobs=[b"\x44" * 10])
        table = self.path_table(h1=original)
        self.assertFalse(push_interface.ensure_push_path(H1, interface, now=5000.0))
        self.assertIs(table[H1], original)
        self.assertEqual(original[:3], [1000.0, b"\x11" * 16, 1])
        self.assertEqual(original[3], 5000.0 + 7 * 24 * 3600)
        self.assertEqual(original[4], [b"\x44" * 10])
        self.assertEqual(original[6], b"\x22" * 32)
        if self.HAS_USED:
            self.assertEqual(original[7], 5000.0)

    def test_ensure_push_path_never_shortens_an_expiry_or_overwrites_a_last_used_time(self):
        interface = StubInterface()
        table = self.path_table(h1=self.entry(interface, expires=1e12, used=1234.5))
        push_interface.ensure_push_path(H1, interface, now=5000.0)
        self.assertEqual(table[H1][3], 1e12)
        if self.HAS_USED:
            self.assertEqual(table[H1][7], 1234.5)

    def test_bind_installs_the_bound_interfaces_path(self):
        # A /register over a connection whose announce Transport never saw still gets a path.
        table = self.path_table()
        self.forget_known_destinations()
        server = self.make_server()
        interface = StubInterface()
        server.bind(H1, interface)
        self.assertIs(table[H1][5], interface)
        self.assertEqual(table[H1][2], 1)

    def test_refused_bind_does_not_touch_the_path(self):
        table = self.path_table()
        server = self.make_server()
        interface = StubInterface()
        interface.IN = False
        server.bind(H1, interface)
        self.assertEqual(table, {})

    @unittest.skipIf(not HAS_USED, "RNS < 1.6.0 does not cull never-used paths")
    def test_rns_culls_a_never_used_path_but_keeps_a_bound_one(self):
        # Pins the 1.6.0 rule the refresh exists for against the real Transport.jobs():
        # two identical stale-but-unexpired entries, one bound, and only the other goes.
        interface = StubInterface()
        RNS.Transport.interfaces.append(interface)
        self.addCleanup(RNS.Transport.interfaces.remove, interface)
        now = time.time()
        learned = now - RNS.Transport.unused_path_linger - 60
        with RNS.Transport.path_table_lock:
            for destination_hash in (H1, H2):
                RNS.Transport.path_table[destination_hash] = [learned, b"\x11" * 16, 1, now + 3600, [], interface, b"\x22" * 32, 0]
                self.addCleanup(RNS.Transport.path_table.pop, destination_hash, None)
        server = self.make_server()
        server.bind(H1, interface)
        RNS.Transport.tables_last_culled = 0
        RNS.Transport.jobs()
        self.assertIn(H1, RNS.Transport.path_table)
        self.assertNotIn(H2, RNS.Transport.path_table)

    # standbys: what a registration is bound to while no connection of its client is

    def registration(self, destination_hash):
        registration = Registration(destination_hash, b"\x05" * 64, b"\xaa", "sandbox", "co.example.push", time.time())
        return registration

    def transport_patched(self):
        for name in ("add_interface", "remove_interface"):
            patcher = mock.patch.object(RNS.Transport, name)
            setattr(self, name, patcher.start())
            self.addCleanup(patcher.stop)

    def test_standby_is_a_dormant_bound_push_client_without_a_socket(self):
        self.transport_patched()
        table = self.path_table()
        self.forget_known_destinations()
        server = self.make_server()
        standby = server.standby(H1)
        self.assertIsInstance(standby, PushClientInterface)
        self.assertTrue(standby.dormant)
        self.assertTrue(standby.online)
        self.assertTrue(standby.OUT and standby.IN)
        self.assertIsNone(standby.socket)
        self.assertEqual(standby.bound_hash, H1)
        self.assertIs(standby.push_server, server)
        self.assertIs(standby.parent_interface, server)
        self.assertIs(server.bindings[H1], standby)
        self.assertIn(standby, server.spawned_interfaces)
        self.add_interface.assert_called_once_with(standby)
        self.assertIs(table[H1][5], standby)
        self.assertIn(H1.hex(), str(standby))

    def test_standby_pushes_what_transport_hands_it(self):
        self.transport_patched()
        self.path_table()
        server = self.make_server()
        standby = server.standby(H1)
        with mock.patch.object(server.dispatcher, "enqueue") as enqueue:
            standby.process_outgoing(make_raw(RNS.Packet.DATA, H1))
            standby.process_outgoing(make_raw(RNS.Packet.DATA, H2))
        enqueue.assert_called_once_with(H1, make_raw(RNS.Packet.DATA, H1), silent=False)

    def test_no_standby_for_a_bound_destination(self):
        self.transport_patched()
        self.path_table()
        server = self.make_server()
        interface = StubInterface()
        server.bind(H1, interface)
        self.assertIsNone(server.standby(H1))
        self.assertIs(server.bindings[H1], interface)
        self.add_interface.assert_not_called()

    def test_a_connection_binding_retires_the_standby_and_takes_over_its_path(self):
        self.transport_patched()
        table = self.path_table()
        server = self.make_server()
        standby = server.standby(H1)
        live = StubInterface()
        server.bind(H1, live)
        self.assertIs(server.bindings[H1], live)
        self.assertFalse(standby.dormant)
        self.assertIsNone(standby.bound_hash)
        self.assertNotIn(standby, server.spawned_interfaces)
        self.remove_interface.assert_called_once_with(standby)
        self.assertIs(table[H1][5], live)

    # a closing unbound connection: the path a client's announce moved onto it goes back

    def unbound_client(self, server):
        """A spawned connection nothing is bound to, as incoming_connection makes one."""
        configuration = {"name": "Client on "+server.name, "target_host": None, "target_port": None,
                         "i2p_tunneled": False}
        interface = PushClientInterface(RNS.Transport, configuration, push_server=server)
        server._adopt(interface, "192.0.2.1", 50000)
        interface.online = True
        server.spawned_interfaces.append(interface)
        return interface

    def test_closing_an_unbound_connection_points_a_moved_path_back_at_the_bound_interface(self):
        # A push-woken client redials, announces over the new connection without binding it, and
        # hangs up within seconds. Transport moved its path onto that connection and would cull
        # the path along with the interface, leaving the bound dormant one unreachable.
        self.transport_patched()
        table = self.path_table()
        self.forget_known_destinations()
        server = self.make_server()
        bound = StubInterface(dormant=True)
        server.bind(H1, bound)
        transient = self.unbound_client(server)
        table[H1] = self.entry(transient, blobs=[b"\x44" * 10])
        transient.teardown()
        self.assertIs(table[H1][5], bound)
        self.assertEqual(table[H1][2], 1)
        self.assertNotIn(b"\x44" * 10, table[H1][4])
        self.assertNotIn(transient, server.spawned_interfaces)
        self.remove_interface.assert_called_once_with(transient)

    def test_restore_paths_through_leaves_paths_of_unbound_destinations_to_transport(self):
        self.transport_patched()
        table = self.path_table()
        self.forget_known_destinations()
        server = self.make_server()
        bound = StubInterface(dormant=True)
        server.bind(H1, bound)
        transient = self.unbound_client(server)
        table[H1] = self.entry(transient)
        table[H2] = other = self.entry(transient)
        self.assertEqual(server.restore_paths_through(transient), [H1])
        self.assertIs(table[H1][5], bound)
        self.assertIs(table[H2], other)

    def test_a_bound_connection_closing_goes_dormant_and_restores_nothing(self):
        self.transport_patched()
        self.path_table()
        self.forget_known_destinations()
        server = self.make_server()
        interface = self.unbound_client(server)
        server.bind(H1, interface)
        with mock.patch.object(server, "restore_paths_through") as restore:
            interface.teardown()
        self.assertTrue(interface.dormant)
        self.assertTrue(interface.online)
        restore.assert_not_called()
        self.remove_interface.assert_not_called()

    def test_ensure_standbys_covers_every_registration_nothing_is_bound_to(self):
        self.transport_patched()
        self.path_table()
        server = self.make_server()
        server.registry.put(self.registration(H1))
        server.registry.put(self.registration(H2))
        bound = StubInterface()
        server.bind(H1, bound)
        server.ensure_standbys()
        self.assertIs(server.bindings[H1], bound)
        self.assertIsInstance(server.bindings[H2], PushClientInterface)
        self.add_interface.assert_called_once_with(server.bindings[H2])

    def test_starting_the_service_stands_in_first(self):
        # Standbys exist before the registration destination announces or answers anything.
        self.transport_patched()
        self.path_table()
        server = self.make_server()
        server.registry.put(self.registration(H1))
        seen = []
        with mock.patch.object(RNS.Transport, "ready", True, create=True), \
                mock.patch.object(server.service, "start", side_effect=lambda identity: seen.append(dict(server.bindings))):
            server._start_service()
        self.assertEqual(list(seen[0]), [H1])
        self.assertTrue(seen[0][H1].dormant)

    def test_maintain_paths_stands_in_and_refreshes_every_binding(self):
        self.transport_patched()
        bound = StubInterface()
        table = self.path_table(h1=self.entry(bound, expires=2000.0), h3=self.entry(StubInterface(), expires=2000.0))
        self.forget_known_destinations()
        server = self.make_server()
        server.registry.put(self.registration(H1))
        server.registry.put(self.registration(H2))
        server.bind(H1, bound)
        table[H1][3] = 2000.0
        server.maintain_paths()
        self.assertGreater(table[H1][3], time.time() + 6 * 24 * 3600)
        self.assertIs(table[H1][5], bound)
        self.assertIs(table[H2][5], server.bindings[H2])
        self.assertTrue(server.bindings[H2].dormant)
        self.assertEqual(table[b"\x03" * 16][3], 2000.0)

    def test_transport_routes_a_relayed_packet_through_the_standby(self):
        # Against the real Transport: a packet in transport addressed to the hub, for a
        # registered destination with no connection, is handed to the standby (as the one-hop
        # packet the client would have read from its socket), and Transport records where to
        # send the proof.
        server = self.make_server()
        standby = server.standby(H1)
        self.addCleanup(server.retire, H1)
        self.addCleanup(RNS.Transport.path_table.pop, H1, None)
        self.assertIn(standby, RNS.Transport.interfaces)
        peer, ours = tcp_pair()
        self.addCleanup(peer.close)
        self.addCleanup(ours.close)
        sender = PushClientInterface(RNS.Transport, {"name": "Client on Push Hub", "target_host": None, "target_port": None,
                                                     "i2p_tunneled": False}, connected_socket=ours, push_server=server)
        server._adopt(sender, "127.0.0.1", "1")
        sender.online = True
        raw = make_raw(RNS.Packet.DATA, H1, header_type=RNS.Packet.HEADER_2, transport_id=RNS.Transport.identity.hash,
                       payload=os.urandom(16))
        with mock.patch.object(server.dispatcher, "enqueue") as enqueue:
            RNS.Transport.inbound(raw, sender)  # queued to Transport's inbound thread
            self.assertTrue(wait_for(lambda: enqueue.called), "Transport never handed the packet to the standby")
        enqueue.assert_called_once()
        destination_hash, pushed = enqueue.call_args.args
        self.assertEqual(destination_hash, H1)
        self.assertEqual(pushed[0] >> 6, RNS.Packet.HEADER_1)
        self.assertEqual(pushed[1], 1)
        self.assertEqual(pushed[2:], raw[18:])
        packet = RNS.Packet(None, raw)
        packet.unpack()
        reverse_entry = RNS.Transport.reverse_table.pop(packet.get_hash()[:16])
        self.assertIs(reverse_entry[0], sender)
        self.assertIs(reverse_entry[1], standby)

    def test_owns_only_its_own_push_clients(self):
        server = self.make_server()
        other = self.make_server()
        peer, ours = tcp_pair()
        self.addCleanup(peer.close)
        self.addCleanup(ours.close)
        config = {"name": "Client", "target_host": None, "target_port": None, "i2p_tunneled": False}
        mine = PushClientInterface(RNS.Transport, config, connected_socket=ours, push_server=server)
        self.assertTrue(server.owns(mine))
        self.assertFalse(other.owns(mine))
        self.assertFalse(server.owns(None))
        self.assertFalse(server.owns(object()))

    def test_detach_stops_the_dispatcher_and_closes_apns(self):
        server = self.make_server()
        server.detach()
        self.assertTrue(server.dispatcher._stopped)
        self.assertTrue(self.apns.closed)

    # discovery

    def test_discovery_announces_the_hub_as_a_tcp_server(self):
        server = self.make_server()
        # What Reticulum's interface setup would set for "discoverable = yes".
        server.reachable_on = "hub.example.net"
        server.discovery_name = "Hub"
        server.discovery_stamp_value = None
        server.discovery_location = None
        server.discovery_latitude = server.discovery_longitude = server.discovery_height = None
        server.discovery_lxmf_address = None
        server.discovery_publish_ifac = False
        server.discovery_encrypt = False
        announcer = Discovery.InterfaceAnnouncer.__new__(Discovery.InterfaceAnnouncer)
        announcer.stamp_cache = {}
        announcer.stamper = mock.Mock(generate_stamp=mock.Mock(return_value=(b"STAMP", 0)))

        data = announcer.get_interface_announce_data(server)

        self.assertIsNotNone(data)
        info = umsgpack.unpackb(data[1:-len(b"STAMP")])
        self.assertEqual(info[Discovery.INTERFACE_TYPE], "TCPServerInterface")
        self.assertEqual(info[Discovery.REACHABLE_ON], "hub.example.net")
        self.assertEqual(info[Discovery.PORT], server.bind_port)

    # shim

    def test_shim_exposes_the_interface_class(self):
        with open(os.path.join(REPO, "rns_push", "shim", "PushTCPServerInterface.py")) as f:
            code = f.read()
        globals_ = {"Interface": Interface, "RNS": RNS}
        exec(code, globals_)
        self.assertIs(globals_["interface_class"], PushTCPServerInterface)


if __name__ == "__main__":
    unittest.main()
