import base64
import json
import os
import shutil
import tempfile
import time
import unittest

from rns_push.dispatcher import PushDispatcher
from rns_push.registry import Registration, Registry
from tests.support import FakeAPNs, FakeClock

DEST = b"\x0d" * 16
OTHER = b"\x0e" * 16
TOKEN = b"\xaa" * 32


def registration(destination_hash=DEST):
    return Registration(destination_hash=destination_hash, identity_public_key=b"\x05" * 64, token=TOKEN,
                        environment="sandbox", bundle_id="co.example.push", registered_at=0.0)


def packets_of(send):
    return json.loads(send[4])["rns"]["packets"]


class DispatcherTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.registry = Registry(os.path.join(self.dir, "registrations.json"))
        self.registry.put(registration())
        self.apns = FakeAPNs()
        self.clock = FakeClock(0.0)
        self.sleeps = []
        self.unregistered = []
        self.dispatcher = PushDispatcher(self.registry, self.apns, self.unregistered.append,
                                         clock=self.clock, sleep=self.sleeps.append, start_thread=False)

    def tearDown(self):
        shutil.rmtree(self.dir)

    def flush_one(self, raw=b"\x01\x02\x03", destination_hash=DEST):
        self.dispatcher.enqueue(destination_hash, raw)
        self.dispatcher.step()
        self.clock.advance(0.5)
        self.dispatcher.step()

    def test_a_single_packet_waits_for_the_half_second_window(self):
        self.dispatcher.enqueue(DEST, b"\x01")
        self.dispatcher.step()
        self.clock.advance(0.49)
        self.dispatcher.step()
        self.assertEqual(self.apns.sends, [])
        self.clock.advance(0.01)
        self.dispatcher.step()
        self.assertEqual(len(self.apns.sends), 1)

    def test_payload_and_send_arguments_are_exact(self):
        self.flush_one(b"\x01\x02\x03")
        expected = (b'{"aps":{"alert":{"title":"New message"},"mutable-content":1,"content-available":1},'
                    b'"rns":{"v":1,"packets":["AQID"]}}')
        self.assertEqual(self.apns.sends, [("sandbox", TOKEN.hex(), "co.example.push", DEST.hex(), expected)])

    def test_eight_packets_flush_immediately(self):
        for i in range(9):
            self.dispatcher.enqueue(DEST, bytes([i]))
        self.dispatcher.step()
        self.assertEqual(len(self.apns.sends), 1)
        self.assertEqual(len(packets_of(self.apns.sends[0])), 8)
        self.clock.advance(0.5)
        self.dispatcher.step()
        self.assertEqual(len(packets_of(self.apns.sends[1])), 1)

    def test_base64_cap_splits_batches(self):
        for i in range(7):
            self.dispatcher.enqueue(DEST, bytes([i]) * 400)
        self.dispatcher.step()
        self.assertEqual(len(self.apns.sends), 1)
        self.assertEqual(len(packets_of(self.apns.sends[0])), 6)
        self.clock.advance(0.5)
        self.dispatcher.step()
        self.assertEqual(len(packets_of(self.apns.sends[1])), 1)

    def test_different_destinations_are_never_batched_together(self):
        self.registry.put(registration(OTHER))
        self.dispatcher.enqueue(DEST, b"\x01")
        self.dispatcher.enqueue(OTHER, b"\x02")
        self.dispatcher.step()
        self.clock.advance(0.5)
        self.dispatcher.step()
        self.assertEqual(sorted(send[3] for send in self.apns.sends), sorted([DEST.hex(), OTHER.hex()]))
        self.assertTrue(all(len(packets_of(send)) == 1 for send in self.apns.sends))

    def test_twenty_first_push_in_a_minute_is_dropped(self):
        for _ in range(21):
            self.flush_one()
        self.assertEqual(len(self.apns.sends), 20)
        self.clock.advance(60)
        self.flush_one()
        self.assertEqual(len(self.apns.sends), 21)

    def test_unregistered_destination_is_dropped(self):
        self.flush_one(destination_hash=OTHER)
        self.assertEqual(self.apns.sends, [])

    def test_registration_removed_during_the_window_drops_the_batch(self):
        self.dispatcher.enqueue(DEST, b"\x01")
        self.dispatcher.step()
        self.registry.remove(DEST)
        self.clock.advance(0.5)
        self.dispatcher.step()
        self.assertEqual(self.apns.sends, [])

    def test_410_unregisters(self):
        self.apns.responses = [(410, "Unregistered")]
        self.flush_one()
        self.assertEqual(self.unregistered, [registration()])

    def test_bad_device_token_and_wrong_topic_unregister(self):
        for reason in ("BadDeviceToken", "DeviceTokenNotForTopic"):
            with self.subTest(reason=reason):
                self.unregistered.clear()
                self.clock.advance(60)
                self.apns.responses = [(400, reason)]
                self.flush_one()
                self.assertEqual(self.unregistered, [registration()])

    def test_other_400_does_not_unregister_or_retry(self):
        self.apns.responses = [(400, "BadTopic")]
        self.flush_one()
        self.assertEqual(self.unregistered, [])
        self.assertEqual(len(self.apns.sends), 1)

    def test_429_is_retried_once_after_a_second(self):
        self.apns.responses = [(429, "TooManyRequests"), (200, None)]
        self.flush_one()
        self.assertEqual(len(self.apns.sends), 2)
        self.assertEqual(self.sleeps, [1.0])

    def test_server_error_retried_once_then_dropped(self):
        self.apns.responses = [(503, None), (503, None), (200, None)]
        self.flush_one()
        self.assertEqual(len(self.apns.sends), 2)

    def test_connection_failure_is_retried(self):
        self.apns.responses = [(0, "connection"), (200, None)]
        self.flush_one()
        self.assertEqual(len(self.apns.sends), 2)

    def test_expired_provider_token_is_refreshed_and_retried(self):
        self.apns.responses = [(403, "ExpiredProviderToken"), (200, None)]
        self.flush_one()
        self.assertEqual(self.apns.invalidations, 1)
        self.assertEqual(len(self.apns.sends), 2)
        self.assertEqual(self.sleeps, [])

    def test_full_queue_drops_the_oldest_packet(self):
        for i in range(1025):
            self.dispatcher.enqueue(DEST, i.to_bytes(2, "big"))
        self.dispatcher.step()
        first = base64.b64decode(packets_of(self.apns.sends[0])[0])
        self.assertEqual(first, (1).to_bytes(2, "big"))

    def test_worker_thread_flushes_on_its_own(self):
        dispatcher = PushDispatcher(self.registry, self.apns, self.unregistered.append)
        try:
            dispatcher.enqueue(DEST, b"\x01")
            deadline = time.monotonic() + 3
            while not self.apns.sends and time.monotonic() < deadline:
                time.sleep(0.05)
            self.assertEqual(len(self.apns.sends), 1)
        finally:
            dispatcher.stop()


if __name__ == "__main__":
    unittest.main()
