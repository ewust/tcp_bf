#!/usr/bin/python

from twisted.internet import reactor
from twisted.application import internet
from twisted.application.service import Application, Service

import txws
#from txws import WebSocketFactory

from WebSocketServerFactory import WebSocketServerFactory

class WebSocketService(Service):
    def __init__(self):
        pass

    def start_service(self, application):
        echoFactory = WebSocketServerFactory(self)
        factory = txws.WebSocketFactory(echoFactory)
        ws_server = internet.TCPServer(8080, factory)
        ws_server.setName('ws-tcp')
        ws_server.setServiceParent(application)
        print "setup"

    def shutdown(self):
        reactor.callLater(0, reactor.stop)



application = Application("ws-streamer")
ws_service = WebSocketService()
ws_service.start_service(application)
