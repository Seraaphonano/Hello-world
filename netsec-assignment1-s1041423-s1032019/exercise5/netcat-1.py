#!/usr/bin/env python3
import socket


"""
This defines s as TCP/IP socket
"""
def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #TCP  

    s.bind((host, port))
    s.listen(backlog)


    for i in [1,2,3]:
        conn, clientaddress = s.accept()
        handle(conn)
        
    s.close()

def handle(passedconn):
    data = b""

# if data:
#     datastring = data.decode("utf-8")
#     print(datastring)

    newdata = passedconn.recv(size)
    while newdata:
        data += newdata
        newdata = passedconn.recv(size)


    if data:
        datastring = data.decode("utf-8")
        print(handlestring(datastring, len("spam "), "\n"))

    passedconn.close()

def handlestring(datastring, length, delimeter):
    stringlist = datastring.split(sep=delimeter)
    filteredlist = []
    for string in stringlist:
        filteredlist.append(string[length:])
    filteredstring = delimeter.join(filteredlist)
    return filteredstring

if __name__ == "__main__":
    host = "localhost"
    port = 42426
    
    backlog = 5
    size = 1024
    main()