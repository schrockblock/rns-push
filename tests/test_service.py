import os
import shutil
import tempfile
import unittest
from unittest import mock

import RNS

from rns_push.registry import REGISTRATION_LIFETIME, Registration, Registry, delivery_hash
from rns_push.service import RegistrationService, load_or_create_identity, path_interface
from tests.support import FakeClock

LINK_ID = b"\x77" * 16
TOKEN = b"\xaa" * 32


class FakeServer:
    def __init__(self):
        self.owned = set()
        self.binds = []
        self.retired = []

    def owns(self, interface):
        return interface is not None and id(interface) in self.owned

    def bind(self, destination_hash, interface):
        self.binds.append((destination_hash, interface))

    def retire(self, destination_hash):
        self.retired.append(destination_hash)


class FakeLink:
    def __init__(self, attached_interface):
        self.attached_interface = attached_interface


class FakeInterface:
    def __init__(self, direct_links=()):
        self.direct_links = set(direct_links)

    def is_direct_link(self, link_id):
        return link_id in self.direct_links


class ServiceTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.clock = FakeClock(1_000_000.0)
        self.registry = Registry(os.path.join(self.dir, "registrations.json"), clock=self.clock)
        self.server = FakeServer()
        self.interface = FakeInterface(direct_links=[LINK_ID])
        self.server.owned.add(id(self.interface))
        self.links = {LINK_ID: FakeLink(self.interface)}
        self.paths = {}
        self.service = RegistrationService(self.server, self.registry, ("co.example.push",), clock=self.clock,
                                           find_link=self.links.get,
                                           path_interface=lambda h: self.paths.get(h, (None, None)))
        self.identity = RNS.Identity()
        self.hash = delivery_hash(self.identity)

    def tearDown(self):
        shutil.rmtree(self.dir)

    def body(self, **overrides):
        body = {"v": 1, "token": TOKEN, "environment": "sandbox", "bundle_id": "co.example.push"}
        body.update(overrides)
        return {k: v for k, v in body.items() if v is not None}

    def register(self, data=None, identity="default", link_id=LINK_ID):
        identity = self.identity if identity == "default" else identity
        return self.service.handle_register("/register", self.body() if data is None else data, b"r", link_id, identity, 0)

    def unregister(self, identity="default"):
        identity = self.identity if identity == "default" else identity
        return self.service.handle_unregister("/unregister", {"v": 1}, b"r", LINK_ID, identity, 0)

    # /register

    def test_register_stores_binds_and_answers(self):
        response = self.register()
        self.assertEqual(response, {"ok": True, "destination_hash": self.hash,
                                    "expires_at": int(1_000_000.0 + REGISTRATION_LIFETIME)})
        stored = self.registry.get(self.hash)
        self.assertEqual(stored, Registration(self.hash, self.identity.get_public_key(), TOKEN, "sandbox",
                                              "co.example.push", 1_000_000.0))
        self.assertEqual(self.server.binds, [(self.hash, self.interface)])

    def test_unidentified_link_is_refused(self):
        self.assertEqual(self.register(identity=None), {"ok": False, "error": "not_identified"})
        self.assertIsNone(self.registry.get(self.hash))

    def test_link_not_over_our_spawned_interface_is_refused(self):
        self.links[LINK_ID] = FakeLink(FakeInterface(direct_links=[LINK_ID]))
        self.assertEqual(self.register(), {"ok": False, "error": "not_direct"})
        self.assertEqual(self.server.binds, [])

    def test_link_whose_request_was_relayed_to_our_interface_is_refused(self):
        # The LINKREQUEST arrived on our spawned interface with hops > 0, so the interface
        # never recorded it as direct: the link was routed through another transport node.
        self.interface.direct_links.clear()
        self.assertEqual(self.register(), {"ok": False, "error": "not_direct"})
        self.assertEqual(self.unregister(), {"ok": False, "error": "not_direct"})
        self.assertEqual(self.server.binds, [])
        self.assertIsNone(self.registry.get(self.hash))

    def test_unknown_link_is_refused(self):
        self.assertEqual(self.register(link_id=b"\x00" * 16), {"ok": False, "error": "not_direct"})

    def test_malformed_bodies_are_bad_requests(self):
        cases = {
            "not a map": [1, 2],
            "wrong version": self.body(v=2),
            "missing token": self.body(token=None),
            "token as hex string": self.body(token=TOKEN.hex()),
            "empty token": self.body(token=b""),
            "oversized token": self.body(token=b"\x01" * 101),
            "unknown environment": self.body(environment="staging"),
            "missing bundle id": self.body(bundle_id=None),
            "bundle id not a string": self.body(bundle_id=b"co.example.push"),
        }
        for name, data in cases.items():
            with self.subTest(name):
                self.assertEqual(self.register(data=data), {"ok": False, "error": "bad_request"})
        self.assertIsNone(self.registry.get(self.hash))

    def test_bundle_outside_the_allow_list_is_refused(self):
        self.assertEqual(self.register(data=self.body(bundle_id="com.other.app")),
                         {"ok": False, "error": "bundle_not_allowed"})

    def test_eleventh_request_in_an_hour_is_rate_limited(self):
        for _ in range(10):
            self.assertTrue(self.register()["ok"])
        self.assertEqual(self.register(), {"ok": False, "error": "rate_limited"})
        self.clock.advance(60 * 60)
        self.assertTrue(self.register()["ok"])

    def test_handler_exception_answers_bad_request(self):
        def broken(link_id):
            raise RuntimeError("boom")
        self.service.find_link = broken
        self.assertEqual(self.register(), {"ok": False, "error": "bad_request"})

    # /unregister

    def test_unregister_removes_and_retires(self):
        self.register()
        self.assertEqual(self.unregister(), {"ok": True})
        self.assertIsNone(self.registry.get(self.hash))
        self.assertEqual(self.server.retired, [self.hash])

    def test_unregister_of_an_unknown_identity_still_succeeds(self):
        self.assertEqual(self.unregister(), {"ok": True})

    def test_unregister_requires_identification(self):
        self.assertEqual(self.unregister(identity=None), {"ok": False, "error": "not_identified"})

    # announces

    def test_announce_for_a_registered_hash_over_our_interface_binds(self):
        self.register()
        new_interface = object()
        self.server.owned.add(id(new_interface))
        self.paths[self.hash] = (new_interface, 1)
        self.service.received_announce(self.hash, self.identity, None)
        self.assertEqual(self.server.binds[-1], (self.hash, new_interface))

    def test_announce_relayed_through_our_interface_from_further_away_is_ignored(self):
        self.register()
        relay = object()
        self.server.owned.add(id(relay))
        self.paths[self.hash] = (relay, 2)
        self.service.received_announce(self.hash, self.identity, None)
        self.assertEqual(self.server.binds, [(self.hash, self.interface)])

    def test_announce_for_an_unregistered_hash_is_ignored(self):
        self.paths[self.hash] = (self.interface, 1)
        self.service.received_announce(self.hash, self.identity, None)
        self.assertEqual(self.server.binds, [])

    def test_announce_arriving_elsewhere_is_ignored(self):
        self.register()
        self.paths[self.hash] = (object(), 1)
        self.service.received_announce(self.hash, self.identity, None)
        self.assertEqual(len(self.server.binds), 1)

    def test_announce_with_a_different_identity_key_is_ignored(self):
        self.register()
        self.paths[self.hash] = (self.interface, 1)
        self.service.received_announce(self.hash, RNS.Identity(), None)
        self.assertEqual(len(self.server.binds), 1)

    def test_aspect_filter_is_lxmf_delivery(self):
        self.assertEqual(RegistrationService.aspect_filter, "lxmf.delivery")

    # sweep

    def test_sweep_retires_expired_registrations(self):
        self.register()
        self.clock.advance(REGISTRATION_LIFETIME)
        self.service.sweep()
        self.assertEqual(self.server.retired, [self.hash])
        self.assertIsNone(self.registry.get(self.hash))

    # stop / deregistration

    def test_stop_on_a_never_started_service_does_not_raise(self):
        self.service.stop()  # must not raise
        self.assertIsNone(self.service.destination)

    def test_stop_after_start_deregisters_the_announce_handler_and_destination(self):
        sentinel = object()
        self.service.destination = sentinel
        with mock.patch.object(RNS.Transport, "deregister_announce_handler") as deregister_handler, \
                mock.patch.object(RNS.Transport, "deregister_destination") as deregister_destination:
            self.service.stop()
        deregister_handler.assert_called_once_with(self.service)
        deregister_destination.assert_called_once_with(sentinel)
        self.assertIsNone(self.service.destination)


class PathInterfaceTests(unittest.TestCase):
    def test_reads_the_receiving_interface_and_hop_count_from_the_path_table(self):
        interface = object()
        entry = [0.0, b"\x01" * 16, 3, 0.0, [], interface, b"\x02" * 32]
        with mock.patch.object(RNS.Transport, "path_table", {b"\x09" * 16: entry}):
            self.assertEqual(path_interface(b"\x09" * 16), (interface, 3))
            self.assertEqual(path_interface(b"\x08" * 16), (None, None))


class IdentityFileTests(unittest.TestCase):
    def test_creates_then_reloads_the_same_identity(self):
        directory = tempfile.mkdtemp()
        try:
            path = os.path.join(directory, "rns_push", "identity")
            created = load_or_create_identity(path)
            self.assertTrue(os.path.isfile(path))
            self.assertEqual(load_or_create_identity(path).hash, created.hash)
        finally:
            shutil.rmtree(directory)


if __name__ == "__main__":
    unittest.main()
