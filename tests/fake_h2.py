import json
import socket
import threading

import h2.config
import h2.connection
import h2.events


class FakeH2Server:
    """In-process HTTP/2 server. connect(host) hands APNsClient the client end of a fresh socket pair."""

    def __init__(self):
        self.requests = []
        self.hosts = []
        self.responses = []
        self.drop_next = False
        self._lock = threading.Lock()

    @property
    def connections(self):
        return len(self.hosts)

    def connect(self, host):
        client, server = socket.socketpair()
        client.settimeout(5)
        self.hosts.append(host)
        threading.Thread(target=self._serve, args=(server,), daemon=True).start()
        return client

    def _next_response(self):
        with self._lock:
            return self.responses.pop(0) if self.responses else (200, None)

    def _serve(self, sock):
        conn = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=False, header_encoding="utf-8"))
        conn.initiate_connection()
        headers, bodies = {}, {}
        try:
            sock.sendall(conn.data_to_send())
            while True:
                data = sock.recv(65535)
                if not data:
                    return
                for event in conn.receive_data(data):
                    if isinstance(event, h2.events.RequestReceived):
                        headers[event.stream_id] = dict(event.headers)
                        bodies[event.stream_id] = b""
                    elif isinstance(event, h2.events.DataReceived):
                        bodies[event.stream_id] += event.data
                        conn.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                    elif isinstance(event, h2.events.StreamEnded):
                        with self._lock:
                            self.requests.append((headers[event.stream_id], bodies[event.stream_id]))
                        if self.drop_next:
                            self.drop_next = False
                            return
                        status, reason = self._next_response()
                        body = json.dumps({"reason": reason}).encode() if reason else b""
                        conn.send_headers(event.stream_id, [(":status", str(status))], end_stream=not body)
                        if body:
                            conn.send_data(event.stream_id, body, end_stream=True)
                out = conn.data_to_send()
                if out:
                    sock.sendall(out)
        except OSError:
            return
        finally:
            sock.close()
