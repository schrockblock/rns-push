import unittest

import RNS

from rns_push.packet import parse_header
from tests.support import make_raw

DEST = bytes(range(16))


class ParseHeaderTests(unittest.TestCase):
    def test_header_1_destination_hash_follows_the_hops_byte(self):
        header = parse_header(make_raw(RNS.Packet.DATA, DEST))
        self.assertEqual(header.header_type, RNS.Packet.HEADER_1)
        self.assertEqual(header.destination_hash, DEST)

    def test_header_2_destination_hash_follows_the_transport_id(self):
        header = parse_header(make_raw(RNS.Packet.DATA, DEST, header_type=RNS.Packet.HEADER_2))
        self.assertEqual(header.header_type, RNS.Packet.HEADER_2)
        self.assertEqual(header.destination_hash, DEST)

    def test_packet_type_is_read_from_the_low_bits(self):
        for packet_type in (RNS.Packet.DATA, RNS.Packet.ANNOUNCE, RNS.Packet.LINKREQUEST, RNS.Packet.PROOF):
            with self.subTest(packet_type=packet_type):
                self.assertEqual(parse_header(make_raw(packet_type, DEST)).packet_type, packet_type)

    def test_ifac_flag_is_reported(self):
        self.assertTrue(parse_header(make_raw(RNS.Packet.DATA, DEST, ifac=True)).ifac)
        self.assertFalse(parse_header(make_raw(RNS.Packet.DATA, DEST)).ifac)

    def test_agrees_with_rns_packet_unpack(self):
        for header_type in (RNS.Packet.HEADER_1, RNS.Packet.HEADER_2):
            for packet_type in (RNS.Packet.DATA, RNS.Packet.PROOF):
                with self.subTest(header_type=header_type, packet_type=packet_type):
                    raw = make_raw(packet_type, DEST, header_type=header_type)
                    packet = RNS.Packet(None, raw)
                    packet.unpack()
                    header = parse_header(raw)
                    self.assertEqual(header.destination_hash, packet.destination_hash)
                    self.assertEqual(header.packet_type, packet.packet_type)

    def test_input_too_short_for_its_header_returns_none(self):
        self.assertIsNone(parse_header(b""))
        self.assertIsNone(parse_header(make_raw(RNS.Packet.DATA, DEST, payload=b"")[:18]))
        self.assertIsNone(parse_header(make_raw(RNS.Packet.DATA, DEST, header_type=RNS.Packet.HEADER_2, payload=b"")[:34]))


if __name__ == "__main__":
    unittest.main()
