#!/usr/bin/env python3

import argparse
import socket
import sys


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


def recv_exact(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("socket closed while reading mqtt data")
        data.extend(chunk)
    return bytes(data)


def decode_remaining_length(sock: socket.socket) -> int:
    multiplier = 1
    value = 0
    while True:
        byte_value = recv_exact(sock, 1)[0]
        value += (byte_value & 0x7F) * multiplier
        if (byte_value & 0x80) == 0:
            return value
        multiplier *= 128
        if multiplier > 128 * 128 * 128:
            raise ValueError("malformed mqtt remaining length")


def build_connect(client_id: str) -> bytes:
    variable = b"\x00\x04MQTT\x04\x02\x00<"
    payload = len(client_id).to_bytes(2, "big") + client_id.encode()
    remaining = encode_remaining_length(len(variable) + len(payload))
    return bytes([0x10]) + remaining + variable + payload


def build_publish(topic: str, message: str) -> bytes:
    topic_bytes = topic.encode()
    payload = len(topic_bytes).to_bytes(2, "big") + topic_bytes + message.encode()
    remaining = encode_remaining_length(len(payload))
    return bytes([0x30]) + remaining + payload


def main() -> int:
    parser = argparse.ArgumentParser(description="Ghostline MQTT host")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--client-id", default="ghostline-host")
    parser.add_argument("--topic", default="demo/topic")
    parser.add_argument("--message", default="hello mqtt payload")
    args = parser.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((args.host, args.port))
    try:
        print(f"MQTT HOST connected to {args.host}:{args.port}", flush=True)
        connect_packet = build_connect(args.client_id)
        sock.sendall(connect_packet)
        print("MQTT HOST tx CONNECT", flush=True)

        first = recv_exact(sock, 1)[0]
        remaining = decode_remaining_length(sock)
        payload = recv_exact(sock, remaining)
        print(f"MQTT HOST rx packet={(first >> 4) & 0x0F} payload={payload.hex()}", flush=True)

        publish_packet = build_publish(args.topic, args.message)
        sock.sendall(publish_packet)
        print(f"MQTT HOST tx PUBLISH topic={args.topic} payload={args.message}", flush=True)
    finally:
        sock.close()
        print("MQTT HOST closed", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
