"""Run an rns-push hub with a file-backed APNs. argv: configdir pushes_path ready_path"""
import json
import os
import sys
import time

import RNS

import rns_push.interface as push_interface


class FileAPNs:
    def __init__(self, path):
        self.path = path

    def send(self, environment, token_hex, topic, collapse_id, payload):
        with open(self.path, "a") as f:
            f.write(json.dumps({"environment": environment, "token": token_hex, "topic": topic,
                                "collapse_id": collapse_id, "payload": payload.decode("utf-8")}) + "\n")
        return 200, None

    def invalidate_token(self):
        pass

    def close(self):
        pass


def main():
    configdir, pushes_path, ready_path = sys.argv[1:4]
    push_interface.make_apns_client = lambda key_pem, key_id, team_id: FileAPNs(pushes_path)
    RNS.Reticulum(configdir=configdir)
    deadline = time.time() + 30
    while time.time() < deadline:
        for interface in list(RNS.Transport.interfaces):
            if isinstance(interface, push_interface.PushTCPServerInterface) and interface.service.destination is not None:
                with open(ready_path + ".tmp", "w") as f:
                    json.dump({"registration_hash": interface.service.destination.hash.hex()}, f)
                os.replace(ready_path + ".tmp", ready_path)
                while True:
                    time.sleep(1)
        time.sleep(0.2)
    sys.exit("the push hub interface did not start")


if __name__ == "__main__":
    main()
