import argparse
import json
import os
import shutil
import time

import RNS

from .registry import REGISTRATION_LIFETIME
from .service import APP_NAME, ASPECT

SHIM_NAME = "PushTCPServerInterface.py"
SHIM_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "shim", SHIM_NAME)


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


def status(configdir):
    state = os.path.join(configdir, "storage", "rns_push")
    identity_path = os.path.join(state, "identity")
    identity = RNS.Identity.from_file(identity_path) if os.path.isfile(identity_path) else None
    if identity is None:
        print("Registration destination: not created yet (start rnsd with a PushTCPServerInterface)")
    else:
        print(f"Registration destination: {RNS.Destination.hash(identity, APP_NAME, ASPECT).hex()}")
    print(f"Registrations: {_live_registrations(os.path.join(state, 'registrations.json'))}")
    return 0


def install_shim(configdir):
    interfaces = os.path.join(configdir, "interfaces")
    os.makedirs(interfaces, exist_ok=True)
    destination = os.path.join(interfaces, SHIM_NAME)
    shutil.copyfile(SHIM_PATH, destination)
    print(destination)
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(prog="rns-push", description="Set up and inspect an rns-push hub")
    commands = parser.add_subparsers(dest="command", required=True)
    status_parser = commands.add_parser("status", help="show the registration destination and registration count")
    status_parser.add_argument("--config", default=None, help="Reticulum config directory")
    install_parser = commands.add_parser("install-shim",
                                         help="copy the interface shim into <config>/interfaces/ so rnsd loads it")
    install_parser.add_argument("--config", default=None, help="Reticulum config directory")
    args = parser.parse_args(argv)

    configdir = args.config or default_configdir()
    if args.command == "install-shim":
        return install_shim(configdir)
    return status(configdir)
