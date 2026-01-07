# lp_client.py
import socket, struct, sys

msg = sys.argv[1].encode()
pkt = struct.pack("!I", len(msg)) + msg

s = socket.socket()
s.connect(("0.0.0.0", 7777))
s.sendall(pkt)

hdr = s.recv(4)
n = struct.unpack("!I", hdr)[0]
data = b""
while len(data) < n:
    data += s.recv(n - len(data))
print(data.decode(errors="replace"))

