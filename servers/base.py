"""On-host server lifecycle base classes."""
import socket
import subprocess
import threading
import time

from framework import log

_log = log.get("server")


class ThreadServer:
    """Threaded UDP server base class. Subclasses implement on_datagram(data, addr) -> bytes|None."""

    def __init__(self, bind_ip="0.0.0.0", port=0):
        self.bind_ip, self.port = bind_ip, port
        self._sock = None
        self._thread = None
        self._stop = threading.Event()
        self.requests = []

    def on_datagram(self, data, addr):
        raise NotImplementedError

    def _serve(self):
        while not self._stop.is_set():
            try:
                self._sock.settimeout(0.5)
                data, addr = self._sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            self.requests.append((data, addr))
            try:
                reply = self.on_datagram(data, addr)
                if reply:
                    self._sock.sendto(reply, addr)
            except Exception as e:  # noqa: BLE001
                _log.debug("server on_datagram error: %s", e)

    def start(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        except OSError:
            pass
        self._sock.bind((self.bind_ip, self.port))
        self.port = self._sock.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        _log.info("%s started on %s:%d", type(self).__name__, self.bind_ip, self.port)
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


class ProcessServer:
    """Subprocess daemon wrapper (e.g. exabgp / tac_plus)."""

    def __init__(self, argv, env=None, ready_wait=2.0):
        self.argv, self.env, self.ready_wait = argv, env, ready_wait
        self.proc = None

    def start(self):
        self.proc = subprocess.Popen(self.argv, env=self.env,
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        time.sleep(self.ready_wait)
        if self.proc.poll() is not None:
            out = self.proc.stdout.read().decode(errors="replace")
            raise RuntimeError(f"server process failed to start: {' '.join(self.argv)}\n{out[-500:]}")
        _log.info("process server started: %s (pid=%d)", self.argv[0], self.proc.pid)
        return self

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.proc.kill()

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()
        return False
