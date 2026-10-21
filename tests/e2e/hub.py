"""Run an rns-push hub with a file-backed APNs. argv: configdir pushes_path ready_path dormant_path

Writes ready_path once the registration destination exists, and dormant_path once any of the
push server's client interfaces has gone dormant."""
import json
import os
import sys
import time

import RNS

import rns_push.interface as push_interface


class FileAPNs:
    def __init__(self, path):
        self.path = path

    def send(self, environment, token_hex, topic, collapse_id, payload, push_type="alert", priority=10):
        with open(self.path, "a") as f:
            f.write(json.dumps({"environment": environment, "token": token_hex, "topic": topic,
                                "collapse_id": collapse_id, "payload": payload.decode("utf-8"),
                                "push_type": push_type, "priority": priority}) + "\n")
        return 200, None

    def invalidate_token(self):
        pass

    def close(self):
        pass


def write_json(path, value):
    with open(path + ".tmp", "w") as f:
        json.dump(value, f)
    os.replace(path + ".tmp", path)


def wait_for_dormancy(server, dormant_path):
    while True:
        bound = [i.bound_hash for i in list(server.spawned_interfaces)
                 if isinstance(i, push_interface.PushClientInterface) and i.dormant]
        bound = [h for h in bound if h is not None]
        if bound:
            write_json(dormant_path, {"bound_hash": bound[0].hex()})
            break
        time.sleep(0.1)
    while True:
        time.sleep(1)


def main():
    configdir, pushes_path, ready_path, dormant_path = sys.argv[1:5]
    push_interface.make_apns_client = lambda key_pem, key_id, team_id: FileAPNs(pushes_path)
    RNS.Reticulum(configdir=configdir)
    deadline = time.time() + 30
    while time.time() < deadline:
        for interface in list(RNS.Transport.interfaces):
            if isinstance(interface, push_interface.PushTCPServerInterface) and interface.service.destination is not None:
                write_json(ready_path, {"registration_hash": interface.service.destination.hash.hex()})
                wait_for_dormancy(interface, dormant_path)
        time.sleep(0.2)
    sys.exit("the push hub interface did not start")


if __name__ == "__main__":
    main()
