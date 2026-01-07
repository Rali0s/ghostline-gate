# lp_server.py

import socket
import struct

s = socket.socket()
s.bind(("127.0.0.1", 8888))
s.listen(5)

print("Length-prefixed server on 8888")

while True:
	c, _ = s.accept()
	print("client connected")
	try:
		while True:
			hdr = c.recv(4)
			if not hdr:
				break
			length = struct.unpack("!I", hdr)[0]
			data = b""
			while len(data) < length:
				chunk = c.recv(length - len(data))
				if not chunk:
					break
				data += chunk

			print("recv:", data)
			# echo back
			c.sendall(struct.pack("!I", len(data)) + data)
	finally:
		c.close()