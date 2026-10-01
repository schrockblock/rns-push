"""Send one packet to the client and report the receipt. argv: configdir client_hex sent_path out_path"""
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
    configdir, client_hex, sent_path, out_path = sys.argv[1:5]
    RNS.Reticulum(configdir=configdir)
    client_hash = bytes.fromhex(client_hex)
    wait_for(lambda: any(getattr(i, "online", False) for i in RNS.Transport.interfaces), 10, "the hub connection")
    RNS.Transport.request_path(client_hash)
    wait_for(lambda: RNS.Transport.has_path(client_hash), 15, "a path to the client")
    destination = RNS.Destination(RNS.Identity.recall(client_hash), RNS.Destination.OUT, RNS.Destination.SINGLE,
                                  "lxmf", "delivery")
    receipt = RNS.Packet(destination, b"wake up").send()
    receipt.set_timeout(20)
    with open(sent_path, "w") as f:
        json.dump({"sent": True}, f)
    deadline = time.time() + 25
    while receipt.status == RNS.PacketReceipt.SENT and time.time() < deadline:
        time.sleep(0.1)
    with open(out_path, "w") as f:
        json.dump({"status": receipt.status}, f)
    os._exit(0)


if __name__ == "__main__":
    main()
