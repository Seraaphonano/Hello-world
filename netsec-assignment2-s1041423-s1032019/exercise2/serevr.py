#!/usr/bin/env python3
import socket
import re

"""
This defines s as TCP/IP socket
"""
def main():

   
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #TCP  

    s.bind((host, port))
    s.listen(backlog)
  
    conn, clientaddress = s.accept()      
    handle(conn)
        
    s.close()

def handle(passedconn):

# if data:
#     datastring = data.decode("utf-8")
#     print(datastring)
    
    data = passedconn.recv(size)

    # while newdata:
    #     data += newdata
    #     newdata = passedconn.recv(size)
    #print(data)
    
    while data:
        match, result= None, None 
        datastring = data.decode("utf-8")
       
        match = re.match(regEX, datastring)
        #print(match.string)
        result = re.findall(r"[A_Za-z0-9-_]", datastring)

        if match:
            result_join = "".join(result)
            action = (match.string)[:5]

            if action =="PRINT":
                print(result_join)
            elif action == "ECHO ":
                passedconn.sendall((result_join+"\n").encode('utf-8')) 
        else: 
            passedconn.sendall(data) 
<<<<<<< HEAD
            raise ValueError("Unknown command")
=======
            error "unknown command"
>>>>>>> 769281ce64f65bc6075d2f1b35dbc7681996badd
        data = passedconn.recv(size) 


    passedconn.close()



if __name__ == "__main__":
    host = "localhost"
    port = 55307
    regEX = "\A(PRINT|ECHO)\s[A_Za-z0-9-_]+(\r\n)\B"
    backlog = 5
    size = 1026

    main()