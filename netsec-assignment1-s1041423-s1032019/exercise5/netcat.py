#!/usr/bin/env python3
import socket

port = 42426

s = socket.create_connection(("localhost", port))

# buf = "Would you like something, sir?".encode("utf-8")

# s.sendall(buf)

Stringbuf = ""
for i in range(0,1000):
    Stringbuf = Stringbuf + "spam" + str(i)+"\n"
buf = Stringbuf.encode("utf-8")
s.sendall(buf)