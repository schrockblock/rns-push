import os
import shutil
import stat
import tempfile
import unittest

import RNS

from rns_push.registry import REGISTRATION_LIFETIME, Registration, Registry, delivery_hash, destination_hash
from tests.support import FakeClock

H1 = b"\x01" * 16
H2 = b"\x02" * 16


def registration(destination_hash=H1, token=b"\xaa" * 32, registered_at=1_000_000.0):
    return Registration(destination_hash=destination_hash, identity_public_key=b"\x05" * 64, token=token,
                        environment="sandbox", bundle_id="co.example.push", registered_at=registered_at)


class RegistryTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "rns_push", "registrations.json")
        self.clock = FakeClock(1_000_000.0)

    def tearDown(self):
        shutil.rmtree(self.dir)

    def make(self):
        return Registry(self.path, clock=self.clock)

    def test_put_then_get(self):
        registry = self.make()
        registry.put(registration())
        self.assertEqual(registry.get(H1), registration())
        # Strengthen: verify entry persists across reload (catches M9 where put doesn't persist)
        reloaded = self.make()
        self.assertEqual(reloaded.get(H1), registration())

    def test_put_replaces_the_entry_for_the_same_hash(self):
        registry = self.make()
        registry.put(registration(token=b"\xaa" * 32))
        registry.put(registration(token=b"\xbb" * 32))
        self.assertEqual(registry.get(H1).token, b"\xbb" * 32)
        self.assertEqual(len(registry.all()), 1)

    def test_remove_reports_whether_an_entry_existed(self):
        registry = self.make()
        registry.put(registration())
        self.assertTrue(registry.remove(H1))
        self.assertFalse(registry.remove(H1))
        self.assertIsNone(registry.get(H1))

    def test_remove_if_token_removes_only_a_matching_registration(self):
        registry = self.make()
        registry.put(registration(token=b"\xaa" * 32))
        self.assertFalse(registry.remove_if_token(H1, b"\xbb" * 32))
        self.assertEqual(registry.get(H1).token, b"\xaa" * 32)
        self.assertFalse(registry.remove_if_token(H2, b"\xaa" * 32))
        self.assertTrue(registry.remove_if_token(H1, b"\xaa" * 32))
        self.assertIsNone(registry.get(H1))
        self.assertIsNone(self.make().get(H1))

    def test_expires_at_is_thirty_days_after_registration(self):
        self.assertEqual(registration(registered_at=100.0).expires_at, 100.0 + REGISTRATION_LIFETIME)
        self.assertEqual(REGISTRATION_LIFETIME, 30 * 24 * 60 * 60)

    def test_expire_removes_only_entries_past_thirty_days(self):
        # Strengthen: verify the constant is correct (catches M3 mutations)
        self.assertEqual(REGISTRATION_LIFETIME, 30 * 24 * 60 * 60)
        registry = self.make()
        registry.put(registration(H1, registered_at=self.clock.now - REGISTRATION_LIFETIME - 1))
        registry.put(registration(H2, registered_at=self.clock.now - REGISTRATION_LIFETIME + 60))
        self.assertEqual(registry.expire(), [H1])
        self.assertIsNone(registry.get(H1))
        self.assertIsNotNone(registry.get(H2))

    def test_entries_survive_a_reload(self):
        registry = self.make()
        registry.put(registration(H1))
        registry.put(registration(H2))
        reloaded = self.make()
        self.assertEqual(sorted(r.destination_hash for r in reloaded.all()), [H1, H2])
        self.assertEqual(reloaded.get(H1), registration(H1))

    def test_removal_and_expiry_are_persisted(self):
        import json
        registry = self.make()
        registry.put(registration(H1))
        registry.put(registration(H2, registered_at=self.clock.now - REGISTRATION_LIFETIME - 1))
        # Verify entries were persisted to disk (catches M9 where put doesn't persist)
        self.assertTrue(os.path.isfile(self.path), "Entries should have been persisted to disk")
        with open(self.path) as f:
            before = json.load(f)
        self.assertGreater(len(before["registrations"]), 0, "File should contain entries")
        registry.remove(H1)
        registry.expire()
        self.assertEqual(self.make().all(), [])

    @unittest.skipUnless(os.name == "posix", "file modes are POSIX")
    def test_registry_file_is_private(self):
        registry = self.make()
        registry.put(registration(H1))
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)
        registry.put(registration(H2))
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)

    def test_corrupt_file_is_set_aside_and_the_registry_starts_empty(self):
        os.makedirs(os.path.dirname(self.path))
        with open(self.path, "w") as f:
            f.write("{not json")
        registry = self.make()
        self.assertEqual(registry.all(), [])
        self.assertTrue(os.path.isfile(self.path + ".corrupt-1000000"))
        self.assertFalse(os.path.exists(self.path))

    def test_failed_write_keeps_the_in_memory_state(self):
        blocker = os.path.join(self.dir, "blocker")
        with open(blocker, "w") as f:
            f.write("a file where a directory should be")
        registry = Registry(os.path.join(blocker, "registrations.json"), clock=self.clock)
        registry.put(registration())
        self.assertEqual(registry.get(H1), registration())


class DeliveryHashTests(unittest.TestCase):
    def test_matches_the_contract_formula(self):
        identity = RNS.Identity()
        name_hash = RNS.Identity.full_hash(b"lxmf.delivery")[:10]
        expected = RNS.Identity.full_hash(name_hash + identity.hash)[:16]
        self.assertEqual(delivery_hash(identity), expected)

    def test_destination_hash_defaults_to_lxmf_delivery(self):
        identity = RNS.Identity()
        self.assertEqual(destination_hash(identity), RNS.Destination.hash(identity, "lxmf", "delivery"))
        self.assertEqual(destination_hash(identity, ("nbhd", "sync")), RNS.Destination.hash(identity, "nbhd", "sync"))


if __name__ == "__main__":
    unittest.main()
