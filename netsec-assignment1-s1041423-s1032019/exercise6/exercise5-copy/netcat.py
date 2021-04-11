#!/usr/bin/env python3
import socket

port = 42428

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) #UDP protocal

# buf = "Would you like something, sir?".encode("utf-8")

# s.sendall(buf)


Stringbuf = ""
for i in range(0,1000):
    Stringbuf = Stringbuf + "spam" + str(i)+"\n"
buf = Stringbuf.encode("utf-8")
print(buf)
s.sendto(buf, ("localhost", port))
