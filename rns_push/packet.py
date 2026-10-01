import collections

import RNS

DST_LEN = RNS.Reticulum.TRUNCATED_HASHLENGTH // 8

Header = collections.namedtuple("Header", "ifac header_type packet_type destination_hash")


def parse_header(raw):
    """Read the unmasked Reticulum header of a raw packet. None when too short."""
    if not raw:
        return None
    flags = raw[0]
    header_type = (flags & 0b01000000) >> 6
    offset = 2 + DST_LEN if header_type == RNS.Packet.HEADER_2 else 2
    if len(raw) < offset + DST_LEN + 1:
        return None
    return Header(ifac=bool(flags & 0x80),
                  header_type=header_type,
                  packet_type=flags & 0b00000011,
                  destination_hash=bytes(raw[offset:offset + DST_LEN]))
