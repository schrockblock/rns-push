import inspect
import os
import threading
import time
import unittest
from unittest import mock

import RNS
from RNS.Interfaces.TCPInterface import HDLC

from rns_push.interface import PushClientInterface
from tests.support import ensure_reticulum, make_raw, tcp_pair

DEST = b"\x0d" * 16
OTHER = b"\x0e" * 16
PROOF_DEST = b"\x0f" * 16


class FakeOwner:
    def __init__(self):
        self.inbound_calls = []

    def inbound(self, data, interface):
        self.inbound_calls.append((data, interface))


class FakeDispatcher:
    def __init__(self):
        self.enqueued = []
        self.silent = []

    def enqueue(self, destination_hash, raw, silent=False):
        self.enqueued.append((destination_hash, raw))
        self.silent.append(silent)


class FakeServer:
    def __init__(self):
        self.dispatcher = FakeDispatcher()
        self.spawned_interfaces = []
        self.rxb = 0
        self.txb = 0
        self.bindings_lock = threading.RLock()


class ClientInterfaceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ensure_reticulum()

    def setUp(self):
        self.owner = FakeOwner()
        self.server = FakeServer()
        self.sockets = []
        patcher = mock.patch.object(RNS.Transport, "remove_interface")
        self.remove_interface = patcher.start()
        self.addCleanup(patcher.stop)

    def tearDown(self):
        for sock in self.sockets:
            sock.close()

    def make(self, server=None):
        server = server or self.server
        peer, ours = tcp_pair()
        self.sockets += [peer, ours]
        interface = PushClientInterface(self.owner, {"name": "Client on Push Hub", "target_host": None,
                                                     "target_port": None, "i2p_tunneled": False},
                                        connected_socket=ours, push_server=server)
        interface.parent_interface = server
        interface.OUT = True
        interface.IN = True
        interface.online = True
        interface.target_ip = "127.0.0.1"
        interface.target_port = "0"
        interface.peer = peer
        server.spawned_interfaces.append(interface)
        return interface

    def dormant(self, server=None):
        interface = self.make(server)
        interface.bound_hash = DEST
        interface.teardown()
        return interface

    def test_push_server_is_a_required_keyword(self):
        parameter = inspect.signature(PushClientInterface.__init__).parameters["push_server"]
        self.assertEqual(parameter.kind, inspect.Parameter.KEYWORD_ONLY)
        self.assertIs(parameter.default, inspect.Parameter.empty)

    # dormancy

    def test_unbound_teardown_is_stock(self):
        interface = self.make()
        interface.teardown()
        self.remove_interface.assert_called_once_with(interface)
        self.assertNotIn(interface, self.server.spawned_interfaces)
        self.assertFalse(interface.OUT)
        self.assertFalse(interface.dormant)

    def test_bound_teardown_goes_dormant_and_stays_attached(self):
        interface = self.dormant()
        self.assertTrue(interface.dormant)
        self.assertTrue(interface.online)
        self.assertTrue(interface.OUT)
        self.assertIn(interface, self.server.spawned_interfaces)
        self.remove_interface.assert_not_called()

    def test_bound_teardown_closes_the_socket(self):
        interface = self.dormant()
        interface.peer.settimeout(2)
        self.assertEqual(interface.peer.recv(1), b"")

    def test_second_teardown_keeps_it_dormant(self):
        interface = self.dormant()
        interface.teardown()
        self.assertTrue(interface.dormant)
        self.assertIn(interface, self.server.spawned_interfaces)
        self.remove_interface.assert_not_called()

    def test_peer_disconnect_during_read_loop_stays_online_while_dormant(self):
        # Stock read_loop sets self.online = False immediately before calling teardown() on a
        # clean peer close (TCPInterface.py:416). teardown() must put online back to True once
        # the interface is bound, or RNS 1.5.5 Transport._inbound() drops its redirected proofs.
        interface = self.make()
        interface.bound_hash = DEST
        thread = threading.Thread(target=interface.read_loop, daemon=True)
        thread.start()
        time.sleep(0.2)
        interface.peer.close()
        thread.join(3)
        self.assertFalse(thread.is_alive())
        self.assertTrue(interface.dormant)
        self.assertTrue(interface.online)
        self.remove_interface.assert_not_called()

    def test_retire_detaches_it_from_transport_and_parent(self):
        interface = self.dormant()
        interface.retire()
        self.remove_interface.assert_called_once_with(interface)
        self.assertNotIn(interface, self.server.spawned_interfaces)
        self.assertFalse(interface.OUT)
        self.assertFalse(interface.dormant)
        self.assertIsNone(interface.bound_hash)

    # pushing

    def test_dormant_pushes_data_and_link_requests_for_the_bound_hash(self):
        interface = self.dormant()
        data = make_raw(RNS.Packet.DATA, DEST)
        link_request = make_raw(RNS.Packet.LINKREQUEST, DEST)
        interface.process_outgoing(data)
        interface.process_outgoing(link_request)
        self.assertEqual(self.server.dispatcher.enqueued, [(DEST, data), (DEST, link_request)])

    def test_dormant_link_request_enqueued_silent(self):
        interface = self.dormant()
        interface.process_outgoing(make_raw(RNS.Packet.LINKREQUEST, DEST))
        interface.process_outgoing(make_raw(RNS.Packet.DATA, DEST))
        self.assertEqual(self.server.dispatcher.silent, [True, False])

    def test_dormant_pushes_header_2_packets(self):
        interface = self.dormant()
        raw = make_raw(RNS.Packet.DATA, DEST, header_type=RNS.Packet.HEADER_2)
        interface.process_outgoing(raw)
        self.assertEqual(self.server.dispatcher.enqueued, [(DEST, raw)])

    def test_dormant_drops_everything_else(self):
        interface = self.dormant()
        interface.process_outgoing(make_raw(RNS.Packet.ANNOUNCE, DEST))
        interface.process_outgoing(make_raw(RNS.Packet.DATA, OTHER))
        interface.process_outgoing(make_raw(RNS.Packet.PROOF, DEST))
        interface.process_outgoing(b"\x00")
        self.assertEqual(self.server.dispatcher.enqueued, [])

    def test_dormant_never_touches_the_socket(self):
        interface = self.dormant()
        interface.socket = mock.Mock()
        interface.process_outgoing(make_raw(RNS.Packet.DATA, DEST))
        interface.socket.sendall.assert_not_called()

    def test_live_interface_writes_the_frame_as_stock(self):
        interface = self.make()
        interface.bound_hash = DEST
        raw = make_raw(RNS.Packet.DATA, DEST)
        interface.process_outgoing(raw)
        interface.peer.settimeout(2)
        expected = bytes([HDLC.FLAG]) + HDLC.escape(raw) + bytes([HDLC.FLAG])
        self.assertEqual(interface.peer.recv(4096), expected)
        self.assertEqual(self.server.dispatcher.enqueued, [])

    # proof redirect

    def reverse_table(self, outbound):
        return mock.patch.object(RNS.Transport, "reverse_table", {PROOF_DEST: [object(), outbound, 0]})

    def test_proof_for_a_dormant_interface_is_attributed_to_it(self):
        dormant = self.dormant()
        fresh = self.make()
        proof = make_raw(RNS.Packet.PROOF, PROOF_DEST)
        with self.reverse_table(dormant):
            fresh.process_incoming(proof)
        self.assertEqual(self.owner.inbound_calls, [(proof, dormant)])
        self.assertEqual(fresh.rxb, len(proof))
        self.assertTrue(dormant.online)

    def test_proof_without_a_reverse_entry_goes_to_self(self):
        fresh = self.make()
        proof = make_raw(RNS.Packet.PROOF, PROOF_DEST)
        with mock.patch.object(RNS.Transport, "reverse_table", {}):
            fresh.process_incoming(proof)
        self.assertEqual(self.owner.inbound_calls, [(proof, fresh)])

    def test_proof_for_a_live_interface_goes_to_self(self):
        live = self.make()
        live.bound_hash = DEST
        fresh = self.make()
        proof = make_raw(RNS.Packet.PROOF, PROOF_DEST)
        with self.reverse_table(live):
            fresh.process_incoming(proof)
        self.assertEqual(self.owner.inbound_calls, [(proof, fresh)])

    def test_proof_for_another_servers_interface_goes_to_self(self):
        foreign = self.dormant(server=FakeServer())
        fresh = self.make()
        proof = make_raw(RNS.Packet.PROOF, PROOF_DEST)
        with self.reverse_table(foreign):
            fresh.process_incoming(proof)
        self.assertEqual(self.owner.inbound_calls, [(proof, fresh)])

    # direct links

    def link_request(self, hops=0, header_type=RNS.Packet.HEADER_1, payload=None):
        raw = bytearray(make_raw(RNS.Packet.LINKREQUEST, PROOF_DEST, header_type=header_type,
                                 payload=payload if payload is not None else os.urandom(RNS.Link.ECPUBSIZE)))
        raw[1] = hops
        return bytes(raw)

    def link_id_of(self, raw):
        packet = RNS.Packet(None, raw)
        packet.unpack()
        return RNS.Link.link_id_from_lr_packet(packet)

    def test_link_request_sent_by_the_neighbour_itself_is_direct(self):
        interface = self.make()
        raw = self.link_request(hops=0)
        interface.process_incoming(raw)
        self.assertTrue(interface.is_direct_link(self.link_id_of(raw)))
        self.assertEqual(self.owner.inbound_calls, [(raw, interface)])

    def test_link_request_with_signalling_bytes_is_direct_under_rns_link_id(self):
        interface = self.make()
        raw = self.link_request(hops=0, header_type=RNS.Packet.HEADER_2,
                                payload=os.urandom(RNS.Link.ECPUBSIZE) + b"\x01\x02\x03")
        interface.process_incoming(raw)
        self.assertTrue(interface.is_direct_link(self.link_id_of(raw)))

    def test_relayed_link_request_is_not_direct(self):
        interface = self.make()
        raw = self.link_request(hops=1)
        interface.process_incoming(raw)
        self.assertFalse(interface.is_direct_link(self.link_id_of(raw)))
        self.assertEqual(self.owner.inbound_calls, [(raw, interface)])

    def test_other_packet_types_are_never_direct_links(self):
        interface = self.make()
        raw = make_raw(RNS.Packet.DATA, PROOF_DEST, payload=os.urandom(RNS.Link.ECPUBSIZE))
        interface.process_incoming(raw)
        self.assertFalse(interface.is_direct_link(self.link_id_of(raw)))

    def test_only_the_most_recent_direct_links_are_kept(self):
        interface = self.make()
        raws = [self.link_request() for _ in range(65)]
        for raw in raws:
            interface.process_incoming(raw)
        self.assertFalse(interface.is_direct_link(self.link_id_of(raws[0])))
        self.assertTrue(all(interface.is_direct_link(self.link_id_of(raw)) for raw in raws[1:]))

    def test_unparseable_link_request_still_reaches_transport(self):
        interface = self.make()
        raw = self.link_request()
        with mock.patch.object(RNS.Link, "link_id_from_lr_packet", side_effect=RuntimeError("boom")):
            interface.process_incoming(raw)
        self.assertEqual(self.owner.inbound_calls, [(raw, interface)])

    def test_non_proof_goes_to_self_even_with_a_matching_reverse_entry(self):
        dormant = self.dormant()
        fresh = self.make()
        data = make_raw(RNS.Packet.DATA, PROOF_DEST)
        with self.reverse_table(dormant):
            fresh.process_incoming(data)
        self.assertEqual(self.owner.inbound_calls, [(data, fresh)])


if __name__ == "__main__":
    unittest.main()
