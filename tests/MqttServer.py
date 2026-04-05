#!/usr/bin/env python3

import argparse
import socket
import sys


def recv_exact(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("socket closed while reading mqtt data")
        data.extend(chunk)
    return bytes(data)


def decode_remaining_length(sock: socket.socket) -> tuple[int, bytes]:
    multiplier = 1
    value = 0
    encoded = bytearray()
    while True:
        byte_value = recv_exact(sock, 1)[0]
        encoded.append(byte_value)
        value += (byte_value & 0x7F) * multiplier
        if (byte_value & 0x80) == 0:
            return value, bytes(encoded)
        multiplier *= 128
        if len(encoded) >= 4:
            raise ValueError("malformed mqtt remaining length")


def encode_remaining_length(value: int) -> bytes:
    out = bytearray()
    while True:
        encoded = value % 128
        value //= 128
        if value > 0:
            encoded |= 0x80
        out.append(encoded)
        if value == 0:
            return bytes(out)


def read_packet(sock: socket.socket) -> tuple[int, bytes]:
    first = recv_exact(sock, 1)
    remaining_length, _ = decode_remaining_length(sock)
    payload = recv_exact(sock, remaining_length)
    return first[0], payload


def send_connack(sock: socket.socket) -> None:
    packet = bytes([0x20, 0x02, 0x00, 0x00])
    sock.sendall(packet)


def parse_publish(payload: bytes, first_byte: int) -> tuple[str, bytes]:
    if len(payload) < 2:
        raise ValueError("publish missing topic length")
    topic_length = (payload[0] << 8) | payload[1]
    if len(payload) < 2 + topic_length:
        raise ValueError("publish missing topic")
    topic = payload[2:2 + topic_length].decode(errors="replace")
    qos = (first_byte >> 1) & 0x03
    offset = 2 + topic_length + (2 if qos > 0 else 0)
    return topic, payload[offset:]


def main() -> int:
    parser = argparse.ArgumentParser(description="Ghostline MQTT upstream server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((args.host, args.port))
    listener.listen(1)
    print(f"MQTT SERVER listening on {args.host}:{args.port}", flush=True)

    conn, addr = listener.accept()
    print(f"MQTT SERVER accepted {addr[0]}:{addr[1]}", flush=True)
    try:
        first, payload = read_packet(conn)
        print(f"MQTT SERVER rx packet={(first >> 4) & 0x0F} bytes={len(payload)}", flush=True)
        if ((first >> 4) & 0x0F) != 1:
            raise ValueError("expected CONNECT packet first")
        send_connack(conn)
        print("MQTT SERVER tx CONNACK", flush=True)

        first, payload = read_packet(conn)
        packet_type = (first >> 4) & 0x0F
        topic, body = parse_publish(payload, first)
        print(
            f"MQTT SERVER rx packet={packet_type} topic={topic} payload={body.decode(errors='replace')}",
            flush=True,
        )
    finally:
        conn.close()
        listener.close()
        print("MQTT SERVER closed", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
