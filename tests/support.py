import os
import socket

import RNS
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))


def ensure_reticulum():
    """One RNS instance per test process. Interface.__init__ needs it."""
    instance = RNS.Reticulum.get_instance()
    if instance is None:
        instance = RNS.Reticulum(configdir=os.path.join(TESTS_DIR, "rnsconfig"), loglevel=RNS.LOG_ERROR)
    return instance


def make_raw(packet_type, destination_hash, header_type=RNS.Packet.HEADER_1, ifac=False,
             transport_id=b"\x11" * 16, context=0, payload=b"payload"):
    flags = (header_type << 6) | packet_type
    if header_type == RNS.Packet.HEADER_2:
        flags |= RNS.Transport.TRANSPORT << 4
    if ifac:
        flags |= 0x80
    raw = bytes([flags, 0])
    if header_type == RNS.Packet.HEADER_2:
        raw += transport_id
    return raw + destination_hash + bytes([context]) + payload


def tcp_pair():
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    client = socket.create_connection(listener.getsockname())
    server_side, _ = listener.accept()
    listener.close()
    return client, server_side


def p256_pem(curve=None):
    key = ec.generate_private_key(curve or ec.SECP256R1())
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    return key, pem


class FakeClock:
    def __init__(self, now=1000.0):
        self.now = now

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


class FakeAPNs:
    def __init__(self):
        self.sends = []
        self.responses = []
        self.invalidations = 0
        self.closed = False

    def send(self, environment, token_hex, topic, collapse_id, payload,
             push_type="alert", priority=10):
        self.sends.append((environment, token_hex, topic, collapse_id, payload,
                           push_type, priority))
        return self.responses.pop(0) if self.responses else (200, None)

    def invalidate_token(self):
        self.invalidations += 1

    def close(self):
        self.closed = True
