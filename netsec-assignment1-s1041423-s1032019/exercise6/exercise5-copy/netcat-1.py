#!/usr/bin/env python3
import socket



def main():
    server= socket.socket(socket.AF_INET, socket.SOCK_DGRAM) #UDP
   
    server.bind((host, port))
    
    data = b""
    received = False
    while not received:
    
        newdata, clientaddress = server.recvfrom(size)
        received = True
        print(newdata.decode('utf-8'))
       
    
    server.close() 

# def handle(passedconn):
#     data = b""

# if data:
#     datastring = data.decode("utf-8")
#     print(datastring)

#     newdata = passedconn.recv(size)
#     while newdata:
#         data += newdata
#         newdata = passedconn.recv(size)


#     if data:
#         datastring = data.decode("utf-8")
#         print(handlestring(datastring, len("spam "), "\n"))

#     passedconn.close()

def handlestring(datastring, length, delimeter):
    stringlist = datastring.split(sep=delimeter)
    filteredlist = []
    for string in stringlist:
        filteredlist.append(string[length:])
    filteredstring = delimeter.join(filteredlist)
    return filteredstring

if __name__ == "__main__":
    host = "localhost"
    port = 42428
    
    backlog = 5
    size = 2**16-1
    main()