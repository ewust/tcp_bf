#!/usr/bin/python

import socket
import time
socks = []

for i in range(1,200):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('', i+2000))
        sock.listen(5)
        sock.setblocking(0)
        socks.append(sock)
    except socket.error:
        print 'out of sockets after %d' % i
        break
    

print 'listening on them all!'

connected = []
addresses = []

while 1:
    for s in socks:
        try:
            (conn_sock, addr) = s.accept()
        except socket.error:
            continue
        conn_sock.setblocking(0)
        #connected.append(conn_sock)
        conn_sock.close()
        print addr[1]
        addresses.append(addr)
        

    #print len(addresses)
          
        
