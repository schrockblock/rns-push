import socket

import RNS
from RNS.Interfaces.TCPInterface import TCPClientInterface
from RNS.Transport import IDX_RT_OUTB_IF

from .packet import parse_header

PUSHABLE_TYPES = (RNS.Packet.DATA, RNS.Packet.LINKREQUEST)


class PushClientInterface(TCPClientInterface):
    """A spawned hub connection. Once bound to a registration, it survives its socket:
    it stays attached to Transport, and what Transport hands it goes out as a push."""

    def __init__(self, owner, configuration, connected_socket=None, push_server=None):
        super().__init__(owner, configuration, connected_socket=connected_socket)
        self.push_server = push_server
        self.bound_hash = None
        self.dormant = False

    def teardown(self):
        if self.bound_hash is None:
            return super().teardown()
        # self.dormant is set first, before anything else, to close the race where a
        # concurrent transmit sees online=False/dormant=False. online is left True: RNS 1.5.5
        # Transport._inbound() drops every inbound packet whose receiving_interface.online is
        # False (Transport.py:1916), which would make a dormant interface's redirected proofs
        # get discarded before the proof branch ever runs.
        was_dormant = self.dormant
        self.dormant = True
        if not was_dormant:
            RNS.log(f"{self} is dormant for {RNS.prettyhexrep(self.bound_hash)}", RNS.LOG_INFO)
        if self.socket is not None:
            try:
                self.socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                self.socket.close()
            except OSError:
                pass

    def retire(self):
        RNS.log(f"Retiring {self}", RNS.LOG_VERBOSE)
        self.dormant = False
        self.bound_hash = None
        self.online = False
        self.OUT = False
        self.IN = False
        parent = self.parent_interface
        if parent is not None:
            while self in parent.spawned_interfaces:
                parent.spawned_interfaces.remove(self)
        RNS.Transport.remove_interface(self)

    def process_outgoing(self, data):
        if not self.dormant:
            return super().process_outgoing(data)
        try:
            header = parse_header(data)
            if header is not None and header.destination_hash == self.bound_hash and header.packet_type in PUSHABLE_TYPES:
                self.push_server.dispatcher.enqueue(header.destination_hash, data)
        except Exception as e:
            RNS.log(f"Could not queue a push from {self}: {e}", RNS.LOG_ERROR)

    def process_incoming(self, data):
        target = self._proof_target(data)
        if target is None:
            return super().process_incoming(data)
        if self.online and not self.detached:
            self.rxb += len(data)
            if self.parent_interface is not None:
                self.parent_interface.rxb += len(data)
            self.owner.inbound(data, target)

    def _proof_target(self, data):
        """Stock Transport forwards a proof only if it arrives on the interface the proved
        packet left through. When that interface is one of our dormant ones, the proof
        arrives on a fresh connection instead, so hand it to Transport as the dormant one's."""
        header = parse_header(data)
        if header is None or header.packet_type != RNS.Packet.PROOF:
            return None
        entry = RNS.Transport.reverse_table.get(header.destination_hash)
        if entry is None:
            return None
        outbound = entry[IDX_RT_OUTB_IF]
        if (isinstance(outbound, PushClientInterface) and outbound is not self and outbound.dormant
                and outbound.push_server is self.push_server):
            return outbound
        return None
