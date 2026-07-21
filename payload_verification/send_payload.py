#!/usr/bin/env python3
import socket
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) not in (2, 4):
        print(f"usage: {sys.argv[0]} PAYLOAD_FILE [HOST PORT]")
        return 2

    payload = Path(sys.argv[1]).read_bytes()
    host = sys.argv[2] if len(sys.argv) == 4 else "127.0.0.1"
    port = int(sys.argv[3]) if len(sys.argv) == 4 else 12345

    with socket.create_connection((host, port), timeout=5) as sock:
        sock.sendall(payload)

    print(f"sent {len(payload)} bytes from {sys.argv[1]} to {host}:{port}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

