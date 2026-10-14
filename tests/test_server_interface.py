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
from RNS.Interfaces.Interface import Interface
from RNS.Interfaces.TCPInterface import TCPServerInterface

import rns_push.interface as push_interface
from rns_push.interface import PushClientInterface, PushSettings, PushTCPServerInterface
from rns_push.registry import Registration
from tests.support import FakeAPNs, ensure_reticulum, p256_pem, tcp_pair

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
H1 = b"\x01" * 16
H2 = b"\x02" * 16


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

    def test_incoming_connection_copies_every_attribute_stock_copies(self):
        def assigned(function):
            return set(re.findall(r"spawned_interface\.(\w+)\s*=(?!=)", inspect.getsource(function)))
        derived_ifac = {"ifac_key", "ifac_identity", "ifac_signature"}
        missing = assigned(TCPServerInterface.incoming_connection) - derived_ifac - assigned(PushTCPServerInterface.incoming_connection)
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

    # shim

    def test_shim_exposes_the_interface_class(self):
        with open(os.path.join(REPO, "rns_push", "shim", "PushTCPServerInterface.py")) as f:
            code = f.read()
        globals_ = {"Interface": Interface, "RNS": RNS}
        exec(code, globals_)
        self.assertIs(globals_["interface_class"], PushTCPServerInterface)


if __name__ == "__main__":
    unittest.main()
