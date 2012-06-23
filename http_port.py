#!/usr/bin/python

import socket
import time
import sys
socks = []

lport = 2000
if len(sys.argv) > 1:
    lport = int(sys.argv[1])


sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('', lport))
sock.listen(50)
sock.setblocking(0)

connected = []
ports = []

sock_to_port = {}

while 1:
    try:
        (conn, addr) = sock.accept()
        conn.setblocking(0)
        connected.append(conn)
        ports.append(addr[1])
        print 'accepted %d (%d total)' % (addr[1], len(ports))
        sock_to_port[conn] = addr[1]
    except socket.error:
        pass


    for c in connected:
        try:
            req = c.recv(0xffff)
        except socket.error:
            continue
    
        c.setblocking(1)
        try:
            host = req.split('\n')[1]
        except IndexError:
            connected.remove(c)
            print 'port %d closed' % (sock_to_port[c])
            continue
        #if "status" in host:
        #    c.send("HTTP/1.1 404 Not Found\r\nX-Cnection: close\r\nContent-Type: text/html; charset=utf-8\r\nDate: Fri, 20 Apr 2012 21:35:00 GMT\r\n\r\n<html>Not here</html>\r\n")
        #    print 'port %d is a 404' % (sock_to_port[c])
        #else:
        if 1:
            c.send("HTTP/1.1 301 Moved Permanently\r\nLocation: http://google.com/?t=%s\r\nContent-Type: text/html;\r\nContent-Length: 0\r\n\r\n" % (str(time.time())))
            print 'port %d is a 301 (%d)' % (sock_to_port[c], len(ports))

        c.setblocking(0)


    if (len(ports) >= 250):
        ports.sort()
        print '----------'
        print ports 
        print '+++OUR GUESS: %d' % ((ports[-1]+1))
        ports = []
        break
