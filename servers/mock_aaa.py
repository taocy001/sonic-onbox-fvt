"""Minimal AAA server: TACACS+ (TCP 49) / RADIUS (UDP 1812).

Only used to verify that the DUT's AAA client actually sends auth requests to the server (recording
the requests). The full auth flow (PAM triggering an actual login) requires on-DUT integration with
a real tac_plus/freeradius, marked VERIFY-ON-HW.
"""
import socket
import threading

from framework import log

from .base import ThreadServer

_log = log.get("aaa")


class MockRadiusServer(ThreadServer):
    """Receive RADIUS Access-Request (UDP 1812), reply with Access-Accept (code 2)."""

    def __init__(self, bind_ip="0.0.0.0", port=1812, secret=b"testing123"):
        super().__init__(bind_ip, port)
        self.secret = secret
        self.access_requests = []

    def on_datagram(self, data, addr):
        if len(data) < 20:
            return None
        code = data[0]
        ident = data[1]
        if code != 1:                       # Access-Request
            return None
        self.access_requests.append(data)
        _log.info("RADIUS Access-Request from %s", addr)
        # Reply with a minimal Access-Accept (does not compute a real authenticator, only proves the client arrived)
        return bytes([2, ident, 0, 20]) + data[4:20]


class MockTacacsServer:
    """Receive TACACS+ on TCP 49: record connection/request bytes to prove the client arrived."""

    def __init__(self, bind_ip="0.0.0.0", port=49):
        self.bind_ip, self.port = bind_ip, port
        self._sock = None
        self._thread = None
        self._stop = threading.Event()
        self.connections = []

    def _serve(self):
        while not self._stop.is_set():
            try:
                self._sock.settimeout(0.5)
                conn, addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                data = conn.recv(4096)
                self.connections.append((addr, data))
                _log.info("TACACS+ connection from %s (%d bytes)", addr, len(data))
            finally:
                conn.close()

    def start(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.bind_ip, self.port))
        self._sock.listen(5)
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        return self

    def stop(self):
        self._stop.set()
        if self._sock:
            self._sock.close()
        if self._thread:
            self._thread.join(timeout=2)

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()
        return False
