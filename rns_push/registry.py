import dataclasses
import json
import os
import threading
import time

import RNS

REGISTRATION_LIFETIME = 30 * 24 * 60 * 60
ENVIRONMENTS = ("production", "sandbox")


@dataclasses.dataclass(frozen=True)
class Registration:
    destination_hash: bytes
    identity_public_key: bytes
    token: bytes
    environment: str
    bundle_id: str
    registered_at: float

    @property
    def expires_at(self):
        return self.registered_at + REGISTRATION_LIFETIME

    def to_json(self):
        return {"destination_hash": self.destination_hash.hex(),
                "identity_public_key": self.identity_public_key.hex(),
                "token": self.token.hex(),
                "environment": self.environment,
                "bundle_id": self.bundle_id,
                "registered_at": self.registered_at}

    @classmethod
    def from_json(cls, item):
        return cls(destination_hash=bytes.fromhex(item["destination_hash"]),
                   identity_public_key=bytes.fromhex(item["identity_public_key"]),
                   token=bytes.fromhex(item["token"]),
                   environment=str(item["environment"]),
                   bundle_id=str(item["bundle_id"]),
                   registered_at=float(item["registered_at"]))


def delivery_hash(identity):
    return RNS.Destination.hash(identity, "lxmf", "delivery")


class Registry:
    def __init__(self, path, clock=time.time):
        self.path = path
        self.clock = clock
        self._lock = threading.Lock()
        self._entries = {}
        self._load()

    def put(self, registration):
        with self._lock:
            self._entries[registration.destination_hash] = registration
            self._persist()

    def get(self, destination_hash):
        with self._lock:
            return self._entries.get(destination_hash)

    def remove(self, destination_hash):
        with self._lock:
            existed = self._entries.pop(destination_hash, None) is not None
            if existed:
                self._persist()
            return existed

    def all(self):
        with self._lock:
            return list(self._entries.values())

    def expire(self):
        now = self.clock()
        with self._lock:
            expired = [h for h, r in self._entries.items() if now >= r.expires_at]
            for h in expired:
                del self._entries[h]
            if expired:
                self._persist()
            return expired

    def _load(self):
        if not os.path.isfile(self.path):
            return
        try:
            with open(self.path) as f:
                data = json.load(f)
            entries = {}
            for item in data["registrations"]:
                registration = Registration.from_json(item)
                entries[registration.destination_hash] = registration
            self._entries = entries
        except Exception as e:
            corrupt = f"{self.path}.corrupt-{int(self.clock())}"
            RNS.log(f"Push registry at {self.path} is unreadable ({e}); moving it to {corrupt} and starting empty", RNS.LOG_ERROR)
            try:
                os.replace(self.path, corrupt)
            except OSError as move_error:
                RNS.log(f"Could not move the unreadable push registry aside: {move_error}", RNS.LOG_ERROR)

    def _persist(self):
        tmp = self.path + ".tmp"
        try:
            os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
            with open(tmp, "w") as f:
                json.dump({"v": 1, "registrations": [r.to_json() for r in self._entries.values()]}, f)
            os.replace(tmp, self.path)
        except Exception as e:
            RNS.log(f"Could not write the push registry to {self.path}: {e}", RNS.LOG_ERROR)
