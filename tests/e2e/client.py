"""Play the phone: announce a destination (default lxmf.delivery), register over a link, exit.
argv: configdir identity_path registration_hex out_path [--aspects dotted.name]"""
import argparse
import json
import os
import sys
import time

import RNS


def wait_for(condition, timeout, what):
    deadline = time.time() + timeout
    while not condition():
        if time.time() > deadline:
            sys.exit(f"timed out waiting for {what}")
        time.sleep(0.1)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("configdir")
    parser.add_argument("identity_path")
    parser.add_argument("registration_hex")
    parser.add_argument("out_path")
    parser.add_argument("--aspects", default="lxmf.delivery")
    args = parser.parse_args()
    configdir, identity_path, registration_hex, out_path = args.configdir, args.identity_path, args.registration_hex, args.out_path
    aspects = args.aspects.split(".")
    RNS.Reticulum(configdir=configdir)
    identity = RNS.Identity.from_file(identity_path)
    delivery = RNS.Destination(identity, RNS.Destination.IN, RNS.Destination.SINGLE, *aspects)
    wait_for(lambda: any(getattr(i, "online", False) for i in RNS.Transport.interfaces), 10, "the hub connection")
    delivery.announce()

    registration_hash = bytes.fromhex(registration_hex)
    RNS.Transport.request_path(registration_hash)
    wait_for(lambda: RNS.Transport.has_path(registration_hash), 15, "a path to the registration destination")
    hub = RNS.Destination(RNS.Identity.recall(registration_hash), RNS.Destination.OUT, RNS.Destination.SINGLE,
                          "rnspush", "registration")
    link = RNS.Link(hub)
    wait_for(lambda: link.status == RNS.Link.ACTIVE, 15, "the registration link")
    link.identify(identity)

    result = {}
    request = {"v": 1, "token": bytes.fromhex("ab" * 32), "environment": "sandbox", "bundle_id": "co.example.push"}
    if aspects != ["lxmf", "delivery"]:
        request["aspects"] = aspects
    link.request("/register", request,
                 response_callback=lambda receipt: result.update(response=receipt.response),
                 failed_callback=lambda receipt: result.update(failed=True))
    wait_for(lambda: result, 15, "the /register response")
    response = result.get("response") or {}
    with open(out_path, "w") as f:
        json.dump({"ok": response.get("ok"), "error": response.get("error"),
                   "destination_hash": response.get("destination_hash", b"").hex()}, f)
    time.sleep(0.5)
    os._exit(0)


if __name__ == "__main__":
    main()
