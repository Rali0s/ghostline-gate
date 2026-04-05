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
    parser = argparse.ArgumentParser(description="Ghostline simulation upstream server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8888)
    parser.add_argument("--reply-prefix", default="server-ack:")
    args = parser.parse_args()

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((args.host, args.port))
    listener.listen(1)

    print(f"SERVER listening on {args.host}:{args.port}", flush=True)
    conn, addr = listener.accept()
    print(f"SERVER accepted {addr[0]}:{addr[1]}", flush=True)
    try:
        header = recv_exact(conn, 4)
        size = struct.unpack("!I", header)[0]
        payload = recv_exact(conn, size)
        print(f"SERVER rx bytes={size} payload={payload.decode(errors='replace')}", flush=True)
        reply = (args.reply_prefix.encode() + payload)
        send_frame(conn, reply)
        print(f"SERVER tx bytes={len(reply)} payload={reply.decode(errors='replace')}", flush=True)
    finally:
        conn.close()
        listener.close()
        print("SERVER closed", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
