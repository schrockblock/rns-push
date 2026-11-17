import base64
import contextlib
import io
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest

import RNS
from RNS.Interfaces.TCPInterface import HDLC

from rns_push import cli
from rns_push.registry import delivery_hash, destination_hash
from tests.support import p256_pem

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
E2E = os.path.join(TESTS_DIR, "e2e")

HUB_CONFIG = """[reticulum]
  enable_transport = Yes
  share_instance = No
  panic_on_interface_error = No

[logging]
  loglevel = 5

[interfaces]
  [[Push Hub]]
    type = PushTCPServerInterface
    enabled = yes
    listen_ip = 127.0.0.1
    listen_port = {port}
    apns_key_file = {key}
    apns_key_id = KEY1234567
    apns_team_id = TEAM123456
    allowed_bundle_ids = co.example.push
    push_aspects = lxmf.delivery, nbhd.sync
"""

CLIENT_CONFIG = """[reticulum]
  enable_transport = No
  share_instance = No

[logging]
  loglevel = 5

[interfaces]
  [[Hub]]
    type = TCPClientInterface
    enabled = yes
    target_host = 127.0.0.1
    target_port = {port}
"""


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_for_file(path, timeout):
    deadline = time.time() + timeout
    while not os.path.isfile(path) or os.path.getsize(path) == 0:
        if time.time() > deadline:
            raise AssertionError(f"timed out waiting for {path}")
        time.sleep(0.1)
    with open(path) as f:
        return f.read()


def implicit_proof(raw, identity):
    packet = RNS.Packet(None, raw)
    packet.unpack()
    flags = (RNS.Packet.HEADER_1 << 6) | (RNS.Transport.BROADCAST << 4) | (RNS.Destination.SINGLE << 2) | RNS.Packet.PROOF
    return bytes([flags, 0]) + packet.packet_hash[:16] + bytes([RNS.Packet.NONE]) + identity.sign(packet.packet_hash)


class EndToEndTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.processes = []
        self.port = free_port()
        _, pem = p256_pem()
        key_path = os.path.join(self.dir, "AuthKey.p8")
        with open(key_path, "wb") as f:
            f.write(pem)
        self.hub_dir = self.config_dir("hub", HUB_CONFIG.format(port=self.port, key=key_path))
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(["install-shim", "--config", self.hub_dir]), 0)
        self.client_dir = self.config_dir("client", CLIENT_CONFIG.format(port=self.port))
        self.sender_dir = self.config_dir("sender", CLIENT_CONFIG.format(port=self.port))
        self.identity = RNS.Identity()
        self.identity_path = os.path.join(self.dir, "client_identity")
        self.identity.to_file(self.identity_path)

    def tearDown(self):
        for process in self.processes:
            process.kill()
            process.wait()
        shutil.rmtree(self.dir)

    def config_dir(self, name, config):
        path = os.path.join(self.dir, name)
        os.makedirs(path)
        with open(os.path.join(path, "config"), "w") as f:
            f.write(config)
        return path

    def spawn(self, name, *args):
        log = open(os.path.join(self.dir, f"{name}.log"), "w")
        self.addCleanup(log.close)
        # The children must import the same rns_push as this test, not whichever copy is installed.
        env = dict(os.environ, PYTHONPATH=os.pathsep.join(filter(None, [os.path.dirname(TESTS_DIR),
                                                                        os.environ.get("PYTHONPATH")])))
        process = subprocess.Popen([sys.executable, os.path.join(E2E, f"{name}.py"), *args],
                                   stdout=log, stderr=subprocess.STDOUT, env=env)
        self.processes.append(process)
        return process

    def path(self, name):
        return os.path.join(self.dir, name)

    def test_a_pushed_packet_is_proved_back_to_the_sender(self):
        self.spawn("hub", self.hub_dir, self.path("pushes.jsonl"), self.path("ready.json"), self.path("dormant.json"))
        registration_hex = json.loads(wait_for_file(self.path("ready.json"), 30))["registration_hash"]

        client = self.spawn("client", self.client_dir, self.identity_path, registration_hex, self.path("registered.json"))
        self.assertEqual(client.wait(timeout=60), 0, "client failed, see client.log")
        registered = json.loads(wait_for_file(self.path("registered.json"), 5))
        client_hex = delivery_hash(self.identity).hex()
        self.assertEqual(registered, {"ok": True, "error": None, "destination_hash": client_hex})
        dormant = json.loads(wait_for_file(self.path("dormant.json"), 15))
        self.assertEqual(dormant, {"bound_hash": client_hex}, "the hub never went dormant, see hub.log")

        self.spawn("sender", self.sender_dir, client_hex, self.path("sent.json"), self.path("receipt.json"))
        wait_for_file(self.path("sent.json"), 40)
        push = json.loads(wait_for_file(self.path("pushes.jsonl"), 20).splitlines()[0])
        self.assertEqual(push["environment"], "sandbox")
        self.assertEqual(push["token"], "ab" * 32)
        self.assertEqual(push["topic"], "co.example.push")
        self.assertEqual(push["collapse_id"], client_hex)
        payload = json.loads(push["payload"])
        self.assertEqual(payload["aps"], {"alert": {"title": "New message"}, "mutable-content": 1, "content-available": 1})
        raw = base64.b64decode(payload["rns"]["packets"][0])

        frame = bytes([HDLC.FLAG]) + HDLC.escape(implicit_proof(raw, self.identity)) + bytes([HDLC.FLAG])
        with socket.create_connection(("127.0.0.1", self.port)) as extension:
            extension.sendall(frame)
            time.sleep(1.0)

        receipt = json.loads(wait_for_file(self.path("receipt.json"), 30))
        self.assertEqual(receipt["status"], RNS.PacketReceipt.DELIVERED, "see hub.log and sender.log")

    def test_after_a_hub_restart_a_registered_client_is_pushed_without_reconnecting(self):
        # Bindings and dormant interfaces live in memory, so a restarted hub starts with no
        # path to the client. Its registration survives, and that alone must be enough to push.
        first = self.spawn("hub", self.hub_dir, self.path("pushes-1.jsonl"), self.path("ready-1.json"), self.path("dormant-1.json"))
        registration_hex = json.loads(wait_for_file(self.path("ready-1.json"), 30))["registration_hash"]
        client = self.spawn("client", self.client_dir, self.identity_path, registration_hex, self.path("registered.json"))
        self.assertEqual(client.wait(timeout=60), 0, "client failed, see client.log")
        client_hex = delivery_hash(self.identity).hex()
        wait_for_file(self.path("dormant-1.json"), 15)

        # The sender learns its path while the first hub is up, then holds its packet.
        self.spawn("sender", self.sender_dir, client_hex, self.path("sent.json"), self.path("receipt.json"),
                   "--pathed", self.path("pathed.json"), "--go", self.path("go"))
        wait_for_file(self.path("pathed.json"), 40)

        first.terminate()
        first.wait(timeout=30)
        second = self.spawn("hub", self.hub_dir, self.path("pushes-2.jsonl"), self.path("ready-2.json"), self.path("dormant-2.json"))
        wait_for_file(self.path("ready-2.json"), 30)
        standby = json.loads(wait_for_file(self.path("dormant-2.json"), 15))
        self.assertEqual(standby, {"bound_hash": client_hex}, "the restarted hub has no standby, see hub.log")

        with open(self.path("go"), "w") as f:
            f.write("go")
        wait_for_file(self.path("sent.json"), 60)
        push = json.loads(wait_for_file(self.path("pushes-2.jsonl"), 20).splitlines()[0])
        self.assertEqual(push["collapse_id"], client_hex)
        raw = base64.b64decode(json.loads(push["payload"])["rns"]["packets"][0])
        self.assertEqual(raw[0] >> 6, RNS.Packet.HEADER_1)
        self.assertFalse(os.path.exists(self.path("pushes-1.jsonl")), "the first hub pushed; the sender did not hold")

        frame = bytes([HDLC.FLAG]) + HDLC.escape(implicit_proof(raw, self.identity)) + bytes([HDLC.FLAG])
        with socket.create_connection(("127.0.0.1", self.port)) as extension:
            extension.sendall(frame)
            time.sleep(1.0)
        receipt = json.loads(wait_for_file(self.path("receipt.json"), 30))
        self.assertEqual(receipt["status"], RNS.PacketReceipt.DELIVERED, "see hub.log and sender.log")
        self.assertEqual(second.poll(), None)

    def test_a_link_to_a_dormant_client_comes_up_on_the_connection_it_wakes_on(self):
        # An LXMF message too large for one packet goes over a link. The LINKREQUEST is pushed;
        # the phone wakes, redials, announces and answers the request on that new connection.
        # Transport will only forward the proof if it arrives on the interface the request left
        # through, and would route the link's packets to the dormant one, so the hub has to hand
        # the link to the new connection.
        self.spawn("hub", self.hub_dir, self.path("pushes.jsonl"), self.path("ready.json"), self.path("dormant.json"))
        registration_hex = json.loads(wait_for_file(self.path("ready.json"), 30))["registration_hash"]
        client = self.spawn("client", self.client_dir, self.identity_path, registration_hex, self.path("registered.json"))
        self.assertEqual(client.wait(timeout=60), 0, "client failed, see client.log")
        client_hex = delivery_hash(self.identity).hex()
        dormant = json.loads(wait_for_file(self.path("dormant.json"), 15))
        self.assertEqual(dormant, {"bound_hash": client_hex}, "the hub never went dormant, see hub.log")

        self.spawn("sender", self.sender_dir, client_hex, self.path("sent.json"), self.path("receipt.json"), "--link")
        wait_for_file(self.path("sent.json"), 40)
        push = json.loads(wait_for_file(self.path("pushes.jsonl"), 20).splitlines()[0])
        payload = json.loads(push["payload"])
        self.assertEqual(payload["aps"], {"content-available": 1}, "a link request is pushed silently")
        raw = base64.b64decode(payload["rns"]["packets"][0])
        self.assertEqual(raw[0] & 0b11, RNS.Packet.LINKREQUEST)
        with open(self.path("pushed.bin"), "wb") as f:
            f.write(raw)

        woken = self.spawn("client", self.client_dir, self.identity_path, registration_hex, self.path("woken.json"),
                           "--wake", self.path("pushed.bin"))
        self.assertEqual(woken.wait(timeout=60), 0, "the woken client failed, see client.log")
        self.assertEqual(json.loads(wait_for_file(self.path("woken.json"), 5)), {"link": True, "data": "over the link"})
        receipt = json.loads(wait_for_file(self.path("receipt.json"), 40))
        self.assertEqual(receipt, {"link": "active", "status": RNS.PacketReceipt.DELIVERED}, "see hub.log and sender.log")

    def test_nbhd_sync_packet_is_pushed(self):
        self.spawn("hub", self.hub_dir, self.path("pushes.jsonl"), self.path("ready.json"), self.path("dormant.json"))
        registration_hex = json.loads(wait_for_file(self.path("ready.json"), 30))["registration_hash"]

        client = self.spawn("client", self.client_dir, self.identity_path, registration_hex, self.path("registered.json"),
                            "--aspects", "nbhd.sync")
        self.assertEqual(client.wait(timeout=60), 0, "client failed, see client.log")
        sync_hex = destination_hash(self.identity, ("nbhd", "sync")).hex()
        self.assertNotEqual(sync_hex, delivery_hash(self.identity).hex())
        registered = json.loads(wait_for_file(self.path("registered.json"), 5))
        self.assertEqual(registered, {"ok": True, "error": None, "destination_hash": sync_hex})
        dormant = json.loads(wait_for_file(self.path("dormant.json"), 15))
        self.assertEqual(dormant, {"bound_hash": sync_hex}, "the hub never went dormant, see hub.log")

        self.spawn("sender", self.sender_dir, sync_hex, self.path("sent.json"), self.path("receipt.json"), "nbhd.sync")
        wait_for_file(self.path("sent.json"), 40)
        push = json.loads(wait_for_file(self.path("pushes.jsonl"), 20).splitlines()[0])
        self.assertEqual(push["topic"], "co.example.push")
        self.assertEqual(push["collapse_id"], sync_hex)
        payload = json.loads(push["payload"])
        raw = base64.b64decode(payload["rns"]["packets"][0])
        packet = RNS.Packet(None, raw)
        packet.unpack()
        self.assertEqual(packet.destination_hash.hex(), sync_hex)


if __name__ == "__main__":
    unittest.main()
