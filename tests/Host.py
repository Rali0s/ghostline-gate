#!/usr/bin/env python3

import argparse
import socket
import struct
import sys


def recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        chunk = sock.recv(size - len(chunks))
        if not chunk:
            raise ConnectionError("socket closed while reading frame")
        chunks.extend(chunk)
    return bytes(chunks)


def send_frame(sock: socket.socket, payload: bytes) -> None:
    sock.sendall(struct.pack("!I", len(payload)) + payload)


def main() -> int:
    parser = argparse.ArgumentParser(description="Ghostline simulation host")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=7777)
    parser.add_argument("--message", default="hello through ghostline")
    args = parser.parse_args()

    payload = args.message.encode()
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((args.host, args.port))
    try:
        print(f"HOST connected to {args.host}:{args.port}", flush=True)
        send_frame(client, payload)
        print(f"HOST tx bytes={len(payload)} payload={args.message}", flush=True)

        header = recv_exact(client, 4)
        size = struct.unpack("!I", header)[0]
        reply = recv_exact(client, size)
        print(f"HOST rx bytes={size} payload={reply.decode(errors='replace')}", flush=True)
    finally:
        client.close()
        print("HOST closed", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
