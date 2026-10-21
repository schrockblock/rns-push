import os
import shutil
import tempfile
import threading
import unittest
from unittest import mock

from rns_push.registry import Registration, Registry
from rns_push.store_watch import MessageStoreWatcher
from tests.support import FakeClock

REGISTERED = b"\xaa" * 16
OTHER = b"\xbb" * 16


class MessageStoreWatcherTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.store = os.path.join(self._tmp.name, "messagestore")
        os.mkdir(self.store)
        self.clock = FakeClock()
        self.registry = Registry(os.path.join(self._tmp.name, "registry.json"), clock=self.clock)
        self.registry.put(Registration(destination_hash=REGISTERED, identity_public_key=b"\x05" * 64,
                                       token=b"\x01" * 32, environment="sandbox", bundle_id="app",
                                       registered_at=self.clock()))
        self.arrivals = []
        self.watcher = MessageStoreWatcher(self.store, self.registry, self.arrivals.append, clock=self.clock)
        self._tick = 0

    def add(self, name, recipient=REGISTERED, body=b"x" * 16):
        self.write(self.store, name, recipient + body)

    def write(self, directory, name, data):
        with open(os.path.join(directory, name), "wb") as f:
            f.write(data)
        self.bump(directory)

    def remove(self, name):
        os.remove(os.path.join(self.store, name))
        self.bump(self.store)

    def bump(self, directory):
        # Directory mtime granularity can hide a change made within the same tick.
        self._tick += 1
        os.utime(directory, ns=(self._tick * 10**9, self._tick * 10**9))

    def test_baseline_files_are_not_pushed(self):
        self.add("aa_1")
        self.assertEqual(self.watcher.poll(), 0)
        self.assertEqual(self.arrivals, [])

    def test_new_file_for_registered_hash_arrives(self):
        self.watcher.poll()
        self.add("bb_2", recipient=REGISTERED, body=OTHER)
        self.assertEqual(self.watcher.poll(), 1)
        self.assertEqual(self.arrivals, [REGISTERED])

    def test_new_file_for_unregistered_hash_is_ignored(self):
        self.watcher.poll()
        self.add("bb_2", recipient=OTHER)
        self.assertEqual(self.watcher.poll(), 0)
        self.assertEqual(self.arrivals, [])

    def test_reappearing_id_not_pushed_again(self):
        self.watcher.poll()
        self.add("bb_2")
        self.watcher.poll()
        self.remove("bb_2")
        self.watcher.poll()
        self.add("bb_3")
        self.watcher.poll()
        self.assertEqual(self.arrivals, [REGISTERED])

    def test_unchanged_directory_skips_listing(self):
        self.bump(self.store)  # old enough to be cached
        real_scandir = os.scandir
        with mock.patch("os.scandir", side_effect=real_scandir) as scandir:
            self.watcher.poll()
            self.watcher.poll()
            self.assertEqual(scandir.call_count, 1)

    def test_short_or_vanished_file_is_skipped(self):
        # A registry that knows every hash, so only the length check can reject a short file.
        anything = mock.Mock()
        watcher = MessageStoreWatcher(self.store, anything, self.arrivals.append, clock=self.clock)
        watcher.poll()
        self.write(self.store, "cc_2", b"12345")
        # Listed, but gone by the time it is opened.
        os.symlink(os.path.join(self._tmp.name, "nowhere"), os.path.join(self.store, "dd_3"))
        self.bump(self.store)
        self.assertEqual(watcher.poll(), 0)
        self.assertEqual(self.arrivals, [])

    def test_same_tick_arrival_is_not_hidden(self):
        wall = FakeClock(100.5)
        watcher = MessageStoreWatcher(self.store, self.registry, self.arrivals.append, clock=self.clock,
                                      wall_clock=wall)
        stamp = 100 * 10**9
        os.utime(self.store, ns=(stamp, stamp))
        watcher.poll()
        with open(os.path.join(self.store, "bb_2"), "wb") as f:
            f.write(REGISTERED * 2)
        os.utime(self.store, ns=(stamp, stamp))
        self.assertEqual(watcher.poll(), 1)
        self.assertEqual(self.arrivals, [REGISTERED])

    def test_unavailable_store_logs_once(self):
        missing = os.path.join(self._tmp.name, "later")
        watcher = MessageStoreWatcher(missing, self.registry, self.arrivals.append, clock=self.clock)
        with mock.patch("rns_push.store_watch.RNS.log") as log:
            watcher.poll()
            watcher.poll()
            self.assertEqual(log.call_count, 1)
            os.mkdir(missing)
            watcher.poll()
            os.rmdir(missing)
            watcher.poll()
            self.assertEqual(log.call_count, 2)

    def test_half_written_file_arrives_once_complete(self):
        self.watcher.poll()
        self.write(self.store, "cc_2", REGISTERED[:5])
        self.assertEqual(self.watcher.poll(), 0)
        self.write(self.store, "cc_2", REGISTERED * 2)
        self.assertEqual(self.watcher.poll(), 1)
        self.assertEqual(self.watcher.poll(), 0)
        self.assertEqual(self.arrivals, [REGISTERED])

    def test_permanently_short_file_stops_forcing_listings(self):
        self.watcher.poll()
        self.write(self.store, "cc_2", b"")
        self.watcher.poll()
        self.clock.advance(61.0)
        self.watcher.poll()
        self.bump(self.store)
        self.watcher.poll()
        real_scandir = os.scandir
        with mock.patch("os.scandir", side_effect=real_scandir) as scandir:
            self.watcher.poll()
            self.assertEqual(scandir.call_count, 0)
        self.assertEqual(self.arrivals, [])

    def test_future_dir_mtime_is_cached(self):
        wall = FakeClock(100.0)
        watcher = MessageStoreWatcher(self.store, self.registry, self.arrivals.append, clock=self.clock,
                                      wall_clock=wall)
        stamp = 200 * 10**9
        os.utime(self.store, ns=(stamp, stamp))
        real_scandir = os.scandir
        with mock.patch("os.scandir", side_effect=real_scandir) as scandir:
            watcher.poll()
            watcher.poll()
            self.assertEqual(scandir.call_count, 1)

    def test_start_twice_runs_one_poller(self):
        with mock.patch("threading.Thread", wraps=threading.Thread) as thread:
            self.watcher.start()
            self.watcher.start()
            self.assertEqual(thread.call_count, 1)
            self.watcher.stop()
            self.assertFalse(self.watcher._thread.is_alive())
            self.watcher.start()
            self.assertEqual(thread.call_count, 2)
            self.assertTrue(self.watcher._thread.is_alive())
            self.watcher.stop()

    def test_recreated_store_is_a_fresh_baseline(self):
        self.add("aa_1")
        self.watcher.poll()
        shutil.rmtree(self.store)
        self.assertEqual(self.watcher.poll(), 0)
        os.mkdir(self.store)
        self.add("aa_1")
        self.add("bb_2")
        self.assertEqual(self.watcher.poll(), 0)
        self.assertEqual(self.arrivals, [])

    def test_missing_store_retries_quietly(self):
        missing = os.path.join(self._tmp.name, "later")
        watcher = MessageStoreWatcher(missing, self.registry, self.arrivals.append, clock=self.clock)
        self.assertEqual(watcher.poll(), 0)
        os.mkdir(missing)
        self.write(missing, "aa_1", REGISTERED * 2)
        self.assertEqual(watcher.poll(), 0)
        self.write(missing, "bb_2", REGISTERED * 2)
        self.assertEqual(watcher.poll(), 1)
        self.assertEqual(self.arrivals, [REGISTERED])


if __name__ == "__main__":
    unittest.main()
