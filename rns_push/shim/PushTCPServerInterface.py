# Reticulum loads external interfaces from the "interfaces" directory of its config.
# `rns-push install-shim` copies this file there (for example ~/.reticulum/interfaces/).
# rns-push must be installed in the same Python environment as rnsd.
from rns_push.interface import PushTCPServerInterface

interface_class = PushTCPServerInterface
