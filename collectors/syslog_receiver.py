"""Syslog UDP receiver — listens for RFC 3164/5424 syslog datagrams.

Note (documented, not built): production deployments across untrusted
segments should use TLS-wrapped syslog (RFC 5425) rather than plain UDP.
"""

from __future__ import annotations

import socket
from typing import Iterator, Optional, Tuple

Line = Tuple[str, str, str, str]


class SyslogReceiver:
    def __init__(self, host: str = "0.0.0.0", port: int = 1514,
                 client_id: str = "trinetra-core", buffer_size: int = 65535) -> None:
        self.host = host
        self.port = port
        self.client_id = client_id
        self.buffer_size = buffer_size
        self._sock: Optional[socket.socket] = None

    def start(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))

    def stop(self) -> None:
        if self._sock:
            self._sock.close()
            self._sock = None

    def iterate(self) -> Iterator[Line]:
        if self._sock is None:
            self.start()
        while True:
            data, addr = self._sock.recvfrom(self.buffer_size)
            try:
                text = data.decode("utf-8", errors="replace").rstrip("\n")
            except UnicodeDecodeError:
                continue
            if text.strip():
                host_hint = addr[0] if addr else ""
                yield text, "syslog", self.client_id, host_hint