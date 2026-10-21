import base64
import json
import unittest
from unittest import mock

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from rns_push import apns
from rns_push.apns import CONNECTION_FAILED, APNsClient, JWTSigner
from tests.fake_h2 import FakeH2Server
from tests.support import FakeClock, p256_pem


def b64url_decode(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


class JWTSignerTests(unittest.TestCase):
    def setUp(self):
        self.key, self.pem = p256_pem()
        self.clock = FakeClock(1_700_000_000.0)
        self.signer = JWTSigner(self.pem, "KEY123", "TEAM456", clock=self.clock)

    def claims(self, token):
        return json.loads(b64url_decode(token.split(".")[1]))

    def test_token_verifies_with_the_public_key_and_carries_the_claims(self):
        token = self.signer.token()
        header_b64, claims_b64, signature_b64 = token.split(".")
        self.assertEqual(json.loads(b64url_decode(header_b64)), {"alg": "ES256", "kid": "KEY123"})
        self.assertEqual(json.loads(b64url_decode(claims_b64)), {"iss": "TEAM456", "iat": 1_700_000_000})
        signature = b64url_decode(signature_b64)
        self.assertEqual(len(signature), 64)
        der = encode_dss_signature(int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big"))
        self.key.public_key().verify(der, f"{header_b64}.{claims_b64}".encode(), ec.ECDSA(hashes.SHA256()))

    def test_token_is_cached_for_fifty_minutes(self):
        first = self.signer.token()
        self.clock.advance(50 * 60 - 1)
        self.assertEqual(self.signer.token(), first)
        self.clock.advance(1)
        self.assertEqual(self.claims(self.signer.token())["iat"], 1_700_000_000 + 50 * 60)

    def test_invalidate_forces_a_fresh_token(self):
        self.signer.token()
        self.clock.advance(5)
        self.signer.invalidate()
        self.assertEqual(self.claims(self.signer.token())["iat"], 1_700_000_005)

    def test_rejects_a_key_that_is_not_p256(self):
        _, pem384 = p256_pem(ec.SECP384R1())
        with self.assertRaises(ValueError):
            JWTSigner(pem384, "KEY123", "TEAM456")

    def test_rejects_garbage(self):
        with self.assertRaises(ValueError):
            JWTSigner(b"not a key", "KEY123", "TEAM456")


class APNsClientTests(unittest.TestCase):
    def setUp(self):
        _, pem = p256_pem()
        self.clock = FakeClock()
        self.signer = JWTSigner(pem, "KEY123", "TEAM456", clock=self.clock)
        self.server = FakeH2Server()
        self.client = APNsClient(self.signer, connect=self.server.connect, clock=self.clock)

    def tearDown(self):
        self.client.close()

    def send(self, environment="sandbox"):
        return self.client.send(environment, "abcd", "co.example.push", "0011", b'{"x":1}')

    def test_posts_to_the_device_path_with_apns_headers_and_body(self):
        self.assertEqual(self.send(), (200, None))
        headers, body = self.server.requests[0]
        self.assertEqual(headers[":method"], "POST")
        self.assertEqual(headers[":scheme"], "https")
        self.assertEqual(headers[":authority"], "api.sandbox.push.apple.com")
        self.assertEqual(headers[":path"], "/3/device/abcd")
        self.assertEqual(headers["authorization"], "bearer " + self.signer.token())
        self.assertEqual(headers["apns-push-type"], "alert")
        self.assertEqual(headers["apns-priority"], "10")
        self.assertEqual(headers["apns-topic"], "co.example.push")
        self.assertEqual(headers["apns-collapse-id"], "0011")
        self.assertEqual(body, b'{"x":1}')
        self.assertEqual(self.server.hosts, ["api.sandbox.push.apple.com"])

    def test_background_push_headers(self):
        self.client.send("sandbox", "abcd", "co.example.push", None, b'{"x":1}',
                         push_type="background", priority=5)
        headers, _ = self.server.requests[0]
        self.assertEqual(headers["apns-push-type"], "background")
        self.assertEqual(headers["apns-priority"], "5")
        self.assertNotIn("apns-collapse-id", headers)

    def test_default_headers_unchanged(self):
        self.send()
        headers, _ = self.server.requests[0]
        self.assertEqual(headers["apns-push-type"], "alert")
        self.assertEqual(headers["apns-priority"], "10")
        self.assertEqual(headers["apns-collapse-id"], "0011")

    def test_production_uses_the_production_host(self):
        self.send("production")
        self.assertEqual(self.server.hosts, ["api.push.apple.com"])

    def test_non_200_returns_the_status_and_reason(self):
        self.server.responses = [(410, "Unregistered")]
        self.assertEqual(self.send(), (410, "Unregistered"))

    def test_reuses_one_connection_per_environment(self):
        self.send()
        self.send()
        self.send("production")
        self.assertEqual(self.server.connections, 2)

    def test_dropped_connection_reports_failure_then_reconnects(self):
        self.server.drop_next = True
        self.assertEqual(self.send(), CONNECTION_FAILED)
        self.assertEqual(self.send(), (200, None))
        self.assertEqual(self.server.connections, 2)

    def test_idle_connection_is_reopened_after_thirty_minutes(self):
        self.send()
        self.clock.advance(30 * 60)
        self.send()
        self.assertEqual(self.server.connections, 2)

    def test_connect_failure_reports_failure(self):
        def refuse(host):
            raise OSError("refused")
        client = APNsClient(self.signer, connect=refuse, clock=self.clock)
        self.assertEqual(client.send("sandbox", "abcd", "co.example.push", "0011", b"{}"), CONNECTION_FAILED)

    def test_response_without_a_status_reports_failure(self):
        with mock.patch.object(apns._Connection, "request", return_value=(None, b"")):
            self.assertEqual(self.send(), CONNECTION_FAILED)
        self.assertEqual(self.send(), (200, None))
        self.assertEqual(self.server.connections, 2)

    def test_invalidate_token_reaches_the_signer(self):
        with mock.patch.object(self.signer, "invalidate") as invalidate:
            self.client.invalidate_token()
        invalidate.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
