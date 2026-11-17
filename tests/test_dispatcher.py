import base64
import json
import os
import shutil
import tempfile
import time
import unittest
from unittest import mock

import RNS

from rns_push.dispatcher import PushDispatcher, build_payload, build_propagated_payload, build_silent_payload
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
        self.assertEqual(self.apns.sends, [("sandbox", TOKEN.hex(), "co.example.push", DEST.hex(), expected, "alert", 10)])

    def test_bundle_title_overrides_the_default(self):
        dispatcher = PushDispatcher(self.registry, self.apns, self.unregistered.append, clock=self.clock,
                                    sleep=lambda s: None, start_thread=False,
                                    titles={"co.example.push": "Neighborhood activity"})
        dispatcher.enqueue(DEST, b"\x01" * 40)
        dispatcher.step()
        self.clock.advance(0.6)
        dispatcher.step()
        payload = json.loads(self.apns.sends[-1][4])
        self.assertEqual(payload["aps"]["alert"]["title"], "Neighborhood activity")

    def test_link_request_goes_silent(self):
        self.dispatcher.enqueue(DEST, b"\x01\x02\x03", silent=True)
        self.dispatcher.step()
        self.clock.advance(0.5)
        self.dispatcher.step()
        expected = build_silent_payload(["AQID"])
        self.assertEqual(expected, b'{"aps":{"content-available":1},"rns":{"v":1,"packets":["AQID"]}}')
        self.assertEqual(self.apns.sends, [("sandbox", TOKEN.hex(), "co.example.push", None, expected, "background", 5)])

    def test_silent_and_alert_never_share_a_batch(self):
        self.dispatcher.enqueue(DEST, b"\x01", silent=True)
        self.dispatcher.enqueue(DEST, b"\x02")
        self.dispatcher.step()
        self.clock.advance(0.5)
        self.dispatcher.step()
        self.assertEqual(sorted(send[5] for send in self.apns.sends), ["alert", "background"])
        self.assertTrue(all(len(packets_of(send)) == 1 for send in self.apns.sends))

    def test_propagated_payload_is_exact(self):
        self.dispatcher.enqueue_propagated(DEST)
        self.dispatcher.step()
        expected = (b'{"aps":{"alert":{"title":"New message"},"mutable-content":1,"content-available":1},'
                    b'"rns":{"v":1,"kind":"propagated","packets":[]}}')
        self.assertEqual(self.apns.sends, [("sandbox", TOKEN.hex(), "co.example.push", None, expected, "alert", 10)])

    def test_propagated_title_comes_from_the_bundle(self):
        dispatcher = PushDispatcher(self.registry, self.apns, self.unregistered.append, clock=self.clock,
                                    sleep=lambda s: None, start_thread=False,
                                    titles={"co.example.push": "Neighborhood activity"})
        dispatcher.enqueue_propagated(DEST)
        dispatcher.step()
        self.assertEqual(self.apns.sends[0][4], build_propagated_payload("Neighborhood activity"))

    def test_two_propagated_arrivals_push_twice(self):
        self.dispatcher.enqueue_propagated(DEST)
        self.dispatcher.enqueue_propagated(DEST)
        self.dispatcher.step()
        self.assertEqual(len(self.apns.sends), 2)

    def test_propagated_push_is_rate_limited_like_data(self):
        for _ in range(21):
            self.dispatcher.enqueue_propagated(DEST)
            self.dispatcher.step()
        self.assertEqual(len(self.apns.sends), 20)

    def test_silent_pushes_never_starve_alerts(self):
        for _ in range(25):
            self.dispatcher.enqueue(DEST, b"\x01", silent=True)
            self.dispatcher.step()
            self.clock.advance(0.5)
            self.dispatcher.step()
        self.dispatcher.enqueue_propagated(DEST)
        self.dispatcher.step()
        self.assertEqual(self.apns.sends[-1][5], "alert")

    def test_silent_pushes_have_their_own_cap(self):
        for _ in range(7):
            self.dispatcher.enqueue(DEST, b"\x01", silent=True)
            self.dispatcher.step()
            self.clock.advance(0.5)
            self.dispatcher.step()
        self.assertEqual(len(self.apns.sends), 6)

    def test_unregistered_destination_not_pushed(self):
        self.dispatcher.enqueue_propagated(OTHER)
        self.dispatcher.step()
        self.assertEqual(self.apns.sends, [])

    def test_unknown_bundle_keeps_new_message(self):
        self.assertEqual(json.loads(build_payload(["AA=="]))["aps"]["alert"]["title"], "New message")

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

    def test_wrong_topic_unregisters_without_a_retry(self):
        self.apns.responses = [(400, "DeviceTokenNotForTopic")]
        self.flush_one()
        self.assertEqual(self.unregistered, [registration()])
        self.assertEqual(len(self.apns.sends), 1)

    def test_bad_device_token_is_retried_in_the_other_environment(self):
        # A Release build run from Xcode claims production for a development-signed (sandbox)
        # token; APNs answers 400 BadDeviceToken. The other environment is tried once.
        self.apns.responses = [(400, "BadDeviceToken"), (200, None)]
        with mock.patch("RNS.log") as log:
            self.flush_one()
        self.assertEqual([s[0] for s in self.apns.sends], ["sandbox", "production"])
        self.assertEqual(self.apns.sends[0][1:], self.apns.sends[1][1:])
        self.assertEqual(self.unregistered, [])
        self.assertEqual(self.sleeps, [])
        messages = [call.args[0] for call in log.call_args_list]
        self.assertTrue(any("production" in m and "sandbox" in m and "correct" in m for m in messages), messages)
        self.assertTrue(any(m.startswith("Pushed 1 packet(s) to") for m in messages), messages)

    def test_an_accepted_retry_corrects_the_registration_for_the_next_push(self):
        self.apns.responses = [(400, "BadDeviceToken"), (200, None)]
        self.flush_one()
        self.assertEqual(self.registry.get(DEST).environment, "production")
        self.assertEqual(self.registry.get(DEST).token, TOKEN)
        self.clock.advance(1)
        self.flush_one()
        self.assertEqual([s[0] for s in self.apns.sends], ["sandbox", "production", "production"])

    def test_bad_device_token_in_both_environments_unregisters(self):
        self.apns.responses = [(400, "BadDeviceToken"), (400, "BadDeviceToken")]
        self.flush_one()
        self.assertEqual([s[0] for s in self.apns.sends], ["sandbox", "production"])
        self.assertEqual(self.unregistered, [registration()])
        self.assertEqual(self.registry.get(DEST).environment, "sandbox")

    def test_a_retry_failing_some_other_way_unregisters_too(self):
        self.apns.responses = [(400, "BadDeviceToken"), (400, "DeviceTokenNotForTopic")]
        self.flush_one()
        self.assertEqual(self.unregistered, [registration()])

    def test_a_correction_never_touches_a_registration_replaced_meanwhile(self):
        replacement = Registration(destination_hash=DEST, identity_public_key=b"\x05" * 64, token=b"\xbb" * 32,
                                   environment="sandbox", bundle_id="co.example.push", registered_at=5.0)
        registry = self.registry

        class ReplacingAPNs(FakeAPNs):
            def send(self, *arguments):
                if not self.sends:
                    registry.put(replacement)
                return super().send(*arguments)

        self.apns = ReplacingAPNs()
        self.apns.responses = [(400, "BadDeviceToken"), (200, None)]
        self.dispatcher = PushDispatcher(self.registry, self.apns, self.unregistered.append,
                                         clock=self.clock, sleep=self.sleeps.append, start_thread=False)
        self.flush_one()
        self.assertEqual(self.registry.get(DEST), replacement)

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

    # A hub at loglevel 5 (verbose) otherwise shows nothing for a push that went out: only drops
    # (debug) and APNs failures (error). One verbose line per accepted push lets a hub log answer
    # "was this packet pushed at all, and when" after the fact.

    def test_an_accepted_packet_push_is_logged_verbosely(self):
        with mock.patch("rns_push.dispatcher.RNS.log") as log:
            self.flush_one(b"\x01\x02\x03")
        self.assertEqual(log.call_args_list,
                         [mock.call("Pushed 1 packet(s) to <0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d> (alert)", RNS.LOG_VERBOSE)])

    def test_an_accepted_propagated_push_is_logged_verbosely(self):
        with mock.patch("rns_push.dispatcher.RNS.log") as log:
            self.dispatcher.enqueue_propagated(DEST)
            self.dispatcher.step()
        self.assertEqual(log.call_args_list,
                         [mock.call("Pushed a propagated arrival to <0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d> (alert)",
                                    RNS.LOG_VERBOSE)])

    def test_a_rejected_push_is_not_logged_as_pushed(self):
        self.apns.responses = [(400, "BadTopic")]
        with mock.patch("rns_push.dispatcher.RNS.log") as log:
            self.flush_one(b"\x01\x02\x03")
        self.assertEqual(len(self.apns.sends), 1)
        self.assertFalse(any("Pushed" in str(call) for call in log.call_args_list))


if __name__ == "__main__":
    unittest.main()
