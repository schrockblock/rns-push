import argparse
import json
import os
import time

import RNS

from .registry import REGISTRATION_LIFETIME
from .service import APP_NAME, ASPECT


def default_configdir():
    """The same search order rnsd uses."""
    if os.path.isfile("/etc/reticulum/config"):
        return "/etc/reticulum"
    user_config = os.path.expanduser("~/.config/reticulum")
    if os.path.isfile(os.path.join(user_config, "config")):
        return user_config
    return os.path.expanduser("~/.reticulum")


def _live_registrations(path):
    try:
        with open(path) as f:
            entries = json.load(f)["registrations"]
    except (OSError, ValueError, KeyError):
        return 0
    now = time.time()
    return sum(1 for entry in entries if now < float(entry["registered_at"]) + REGISTRATION_LIFETIME)


def main(argv=None):
    parser = argparse.ArgumentParser(prog="rns-push", description="Inspect an rns-push hub's state")
    commands = parser.add_subparsers(dest="command", required=True)
    status = commands.add_parser("status", help="show the registration destination and registration count")
    status.add_argument("--config", default=None, help="Reticulum config directory")
    args = parser.parse_args(argv)

    state = os.path.join(args.config or default_configdir(), "storage", "rns_push")
    identity_path = os.path.join(state, "identity")
    identity = RNS.Identity.from_file(identity_path) if os.path.isfile(identity_path) else None
    if identity is None:
        print("Registration destination: not created yet (start rnsd with a PushTCPServerInterface)")
    else:
        print(f"Registration destination: {RNS.Destination.hash(identity, APP_NAME, ASPECT).hex()}")
    print(f"Registrations: {_live_registrations(os.path.join(state, 'registrations.json'))}")
    return 0
