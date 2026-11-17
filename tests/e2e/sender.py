"""Send one packet to the client and report the receipt.
argv: configdir client_hex sent_path out_path [dotted.aspects] [--pathed FILE] [--go FILE] [--link]

With --pathed, writes FILE once the path to the client is known; with --go, waits for FILE to
exist before sending, so a test can restart the hub in between. With --link, the packet goes
over a link to the client (what an LXMF message too large for one packet does), and the report
also says whether the link came up."""
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


def hub_online():
    return any(getattr(i, "online", False) for i in RNS.Transport.interfaces)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("configdir")
    parser.add_argument("client_hex")
    parser.add_argument("sent_path")
    parser.add_argument("out_path")
    parser.add_argument("aspects", nargs="?", default="lxmf.delivery")
    parser.add_argument("--pathed")
    parser.add_argument("--go")
    parser.add_argument("--link", action="store_true")
    args = parser.parse_args()
    aspects = args.aspects.split(".")
    RNS.Reticulum(configdir=args.configdir)
    client_hash = bytes.fromhex(args.client_hex)
    wait_for(hub_online, 10, "the hub connection")
    RNS.Transport.request_path(client_hash)
    wait_for(lambda: RNS.Transport.has_path(client_hash), 15, "a path to the client")
    if args.pathed:
        with open(args.pathed, "w") as f:
            json.dump({"pathed": True}, f)
    if args.go:
        wait_for(lambda: os.path.isfile(args.go), 60, "the go file")
        wait_for(hub_online, 30, "the hub connection to come back")
    destination = RNS.Destination(RNS.Identity.recall(client_hash), RNS.Destination.OUT, RNS.Destination.SINGLE,
                                  *aspects)
    report = {}
    if args.link:
        link = RNS.Link(destination)
        with open(args.sent_path, "w") as f:
            json.dump({"sent": True, "link": True}, f)
        deadline = time.time() + 40
        while link.status not in (RNS.Link.ACTIVE, RNS.Link.CLOSED) and time.time() < deadline:
            time.sleep(0.1)
        report["link"] = {RNS.Link.ACTIVE: "active", RNS.Link.CLOSED: "closed"}.get(link.status, "pending")
        if link.status != RNS.Link.ACTIVE:
            with open(args.out_path, "w") as f:
                json.dump(dict(report, status=None), f)
            os._exit(0)
        receipt = RNS.Packet(link, b"over the link").send()
    else:
        receipt = RNS.Packet(destination, b"wake up").send()
        with open(args.sent_path, "w") as f:
            json.dump({"sent": True}, f)
    receipt.set_timeout(20)
    deadline = time.time() + 25
    while receipt.status == RNS.PacketReceipt.SENT and time.time() < deadline:
        time.sleep(0.1)
    with open(args.out_path, "w") as f:
        json.dump(dict(report, status=receipt.status), f)
    os._exit(0)


if __name__ == "__main__":
    main()
