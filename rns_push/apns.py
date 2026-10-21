import base64
import json
import socket
import ssl
import time

import h2.config
import h2.connection
import h2.events
import RNS
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

HOSTS = {"production": "api.push.apple.com", "sandbox": "api.sandbox.push.apple.com"}
CONNECTION_FAILED = (0, "connection")
JWT_LIFETIME = 50 * 60
IDLE_REOPEN = 30 * 60


def _b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=")


def _compact_json(value):
    return json.dumps(value, separators=(",", ":")).encode("utf-8")


class JWTSigner:
    """ES256 provider token for APNs token-based auth, cached for 50 minutes."""

    def __init__(self, key_pem, key_id, team_id, clock=time.time):
        try:
            key = serialization.load_pem_private_key(key_pem, password=None)
        except Exception as e:
            raise ValueError(f"APNs key is not a readable PEM private key: {e}")
        if not isinstance(key, ec.EllipticCurvePrivateKey) or key.curve.name != "secp256r1":
            raise ValueError("APNs key must be a P-256 (ES256) private key")
        self._key = key
        self.key_id = key_id
        self.team_id = team_id
        self.clock = clock
        self._token = None
        self._issued_at = None

    def token(self):
        now = self.clock()
        if self._token is None or now - self._issued_at >= JWT_LIFETIME:
            signing_input = (_b64url(_compact_json({"alg": "ES256", "kid": self.key_id})) + b"." +
                             _b64url(_compact_json({"iss": self.team_id, "iat": int(now)})))
            r, s = decode_dss_signature(self._key.sign(signing_input, ec.ECDSA(hashes.SHA256())))
            signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
            self._token = (signing_input + b"." + _b64url(signature)).decode("ascii")
            self._issued_at = now
        return self._token

    def invalidate(self):
        self._token = None


def tls_connect(host, port=443, timeout=10):
    context = ssl.create_default_context()
    context.set_alpn_protocols(["h2"])
    raw = socket.create_connection((host, port), timeout=timeout)
    tls = context.wrap_socket(raw, server_hostname=host)
    if tls.selected_alpn_protocol() != "h2":
        tls.close()
        raise ConnectionError(f"{host} did not negotiate HTTP/2")
    return tls


class _Connection:
    def __init__(self, sock, now):
        self.sock = sock
        self.closed = False
        self.last_used = now
        self.h2 = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=True, header_encoding="utf-8"))
        self.h2.initiate_connection()
        self.sock.sendall(self.h2.data_to_send())

    def request(self, headers, body):
        stream_id = self.h2.get_next_available_stream_id()
        self.h2.send_headers(stream_id, headers)
        self.h2.send_data(stream_id, body, end_stream=True)
        self.sock.sendall(self.h2.data_to_send())
        status, chunks = None, []
        while True:
            data = self.sock.recv(65535)
            if not data:
                self.closed = True
                raise ConnectionError("APNs closed the connection")
            for event in self.h2.receive_data(data):
                if isinstance(event, h2.events.ResponseReceived) and event.stream_id == stream_id:
                    status = int(dict(event.headers)[":status"])
                elif isinstance(event, h2.events.DataReceived) and event.stream_id == stream_id:
                    chunks.append(event.data)
                    self.h2.acknowledge_received_data(event.flow_controlled_length, stream_id)
                elif isinstance(event, h2.events.StreamReset) and event.stream_id == stream_id:
                    raise ConnectionError("APNs reset the stream")
                elif isinstance(event, h2.events.ConnectionTerminated):
                    self.closed = True
                elif isinstance(event, h2.events.StreamEnded) and event.stream_id == stream_id:
                    pending = self.h2.data_to_send()
                    if pending:
                        self.sock.sendall(pending)
                    return status, b"".join(chunks)
            pending = self.h2.data_to_send()
            if pending:
                self.sock.sendall(pending)

    def close(self):
        self.closed = True
        try:
            self.sock.close()
        except OSError:
            pass


class APNsClient:
    """Synchronous APNs sender. One HTTP/2 connection per environment. Not thread-safe:
    only the dispatcher thread calls send()."""

    def __init__(self, signer, connect=tls_connect, clock=time.monotonic):
        self.signer = signer
        self._connect = connect
        self.clock = clock
        self._connections = {}

    def send(self, environment, token_hex, topic, collapse_id, payload,
             push_type="alert", priority=10):
        host = HOSTS[environment]
        headers = [(":method", "POST"), (":scheme", "https"), (":authority", host),
                   (":path", f"/3/device/{token_hex}"),
                   ("authorization", f"bearer {self.signer.token()}"),
                   ("apns-push-type", push_type), ("apns-priority", str(priority)),
                   ("apns-topic", topic)]
        if collapse_id is not None:
            headers.append(("apns-collapse-id", collapse_id))
        headers += [("content-type", "application/json"), ("content-length", str(len(payload)))]
        try:
            connection = self._connection(environment, host)
            status, body = connection.request(headers, payload)
            connection.last_used = self.clock()
        except Exception as e:
            RNS.log(f"APNs request to {host} failed: {e}", RNS.LOG_WARNING)
            self._drop(environment)
            return CONNECTION_FAILED
        if connection.closed:
            self._drop(environment)
        if status is None:
            RNS.log(f"APNs response from {host} had no status", RNS.LOG_WARNING)
            self._drop(environment)
            return CONNECTION_FAILED
        reason = None
        if status != 200:
            try:
                reason = json.loads(body.decode("utf-8")).get("reason")
            except Exception:
                reason = None
        return status, reason

    def invalidate_token(self):
        self.signer.invalidate()

    def close(self):
        for environment in list(self._connections):
            self._drop(environment)

    def _connection(self, environment, host):
        connection = self._connections.get(environment)
        if connection is not None and (connection.closed or self.clock() - connection.last_used >= IDLE_REOPEN):
            self._drop(environment)
            connection = None
        if connection is None:
            connection = _Connection(self._connect(host), self.clock())
            self._connections[environment] = connection
        return connection

    def _drop(self, environment):
        connection = self._connections.pop(environment, None)
        if connection is not None:
            connection.close()
