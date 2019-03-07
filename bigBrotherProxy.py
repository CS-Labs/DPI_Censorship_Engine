import os
import time
import gzip
import zlib
import subprocess
import argparse
from contextlib import contextmanager
from abc import ABC
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from http.client import HTTPResponse
from ssl import wrap_socket
from socket import socket

class CensorshipEngine(object):
    
    def process(self, bBody):
        # TODO: Add options to do body modification in-line (blocking, same thread)
        # and recording off-line (different thread, none-blocking). The later will need some form of work queueing. 
        if bBody:
            print(bBody)

class CA(object):

    def __init__(self, sKeyPath, sCrtPath):
        self.sKeyPath = sKeyPath
        self.sCrtPath = sCrtPath

    def sign(self, sServerCrs):
        return "openssl x509 -req -in {0} -CA {1} -CAkey {2} -CAcreateserial".format(sServerCrs, self.sCrtPath, self.sKeyPath) 


class AuthenticationManager(object):

    def __init__(self, oCA, sAuthStorePath, sServPKey):
        self.oCA = oCA
        self.sAuthStorePath = sAuthStorePath
        # TODO: Should cache remain between runs?
        self.sCertCache = os.path.join(os.getcwd(), 'certCache')
        if not os.path.exists(self.sCertCache):
            os.mkdir(self.sCertCache)
        self.sServPKey = sServPKey
        
    def genCert(self, sHost, sCert):
        sServerCrs = os.path.join(self.sCertCache, '{0}.csr'.format(sHost))
        sCsrGenCmd = "openssl req -new -sha256 -key {0} -subj '/CN={1}' -out {2}".format(self.sServPKey, sHost, sServerCrs)
        sCASignCmd = self.oCA.sign(sServerCrs)
        sCmd = "{{ cat {0}; {1} && {2}; }} > {3}".format(self.sServPKey, sCsrGenCmd, sCASignCmd, sCert)
        os.system(sCmd) # TODO make this blocking for some reason the subprocess module is losing paths. 
        time.sleep(5) # Temporary until prior is blocking..

    def getCert(self, sHost):
        sCert = os.path.join(self.sCertCache , '{0}.crt'.format(sHost))
        if not os.path.exists(sCert): # Need to generate.
            self.genCert(sHost, sCert)
        return sCert


# TODO: Support more. 
class CONTENT_ENCODINGS(object):
    GZIP = 'gzip'

class CONTENT_TYPES(object):
    HTML = 'text/html'

class Relay(ABC):
    def relay(self, bData):
        pass

class ClientServerRelay(Relay):
    def __init__(self, sHost, iPort):
        self.oSock = socket()
        self.iPort = iPort
        self.sHost = sHost

    def connect(self, iTimeout, bTLS):
        self.oSock.settimeout(iTimeout)
        self.oSock.connect((self.sHost, self.iPort))
        if bTLS:
            self.oSock = wrap_socket(self.oSock)

    def disconnect(self):
        self.oSock.close()

    def relay(self, bData):
        self.oSock.sendall(bData)

    def getServerResponse(self, sHttpVer):
        return HTTPResponseWrapper(self.oSock, sHttpVer)

class ServerClientRelay(object):

    def __new__(cls, oSock, sCertPath):
        return wrap_socket(oSock, server_side=True, certfile=sCertPath)

class HTTPResponseWrapper(object):
    def __init__(self, oSock, sHttpVer):
        self.oHTTPResponse = HTTPResponse(oSock)
        self.oHTTPResponse.begin()
        self.bBody = self.oHTTPResponse.read()
        self.bResponseLine = '{0} {1} {2}\r\n'.format(sHttpVer, self.oHTTPResponse.status, self.oHTTPResponse.reason).encode()
        self.bHeaders = self.oHTTPResponse.msg.as_bytes()
        self.sEncoding = self.oHTTPResponse.getheader('Content-Encoding')
        self.sContentType = self.oHTTPResponse.getheader('Content-Type')
        self.oHTTPResponse.close()

    def __bytes__(self):
        return self.bResponseLine + self.bHeaders + self.bBody

    def getDecodedBody(self):
        if self.sEncoding == CONTENT_ENCODINGS.GZIP and CONTENT_TYPES.HTML in self.sContentType:
            try:
                return zlib.decompress(self.bBody, 16+zlib.MAX_WBITS)
            except Exception as e:
                print("Error decompressing gzip contents {0}".format(str(e)))
               

class HTTPRequestWrapper(object):
    def __init__(self, sReqLine, sHeaders, sBody):
        self.sReqLine = sReqLine
        self.sHeaders = sHeaders
        self.sBody = sBody

    def __repr__(self):
        sReq = '{0}\r\n{1}\r\n'.format(self.sReqLine, self.sHeaders)
        if self.sBody:
            sReq += self.sBody
        return sReq
    def encode(self):
        return str(self).encode()
            
class ProxyMessageHandler(BaseHTTPRequestHandler):

    def __init__(self, request, client_address, server):
        self.bTunneling = False
        BaseHTTPRequestHandler.__init__(self, request, client_address, server)

    @contextmanager
    def handleProxyError(self):
        try:
            yield # Run the body of the context.
        except Exception as e:  # TODO Add custom exceptions.
            self.send_error(418, str(e)) # :)
            

    def establishServerRelayConnection(self):
        self.hostname, self.port = self.path.split(':')
        self.oClientServerRelay = ClientServerRelay(self.hostname, int(self.port))
        self.oClientServerRelay.connect(15, self.bTunneling)
        self.send_response(200, 'Connection established')
        self.end_headers()

    def establishClientRelayConnection(self):
        self.request = ServerClientRelay(self.request, oAuthManager.getCert(self.path.split(':')[0])) #getCa(self.path.split(':')[0]))
        self.setup()

    def do_CONNECT(self):
        # Connect means we want to setup a tunnel through the proxy.
        self.bTunneling = True
        with self.handleProxyError():
            # Connect to destination first, (since we generate certs on the fly..)
            self.establishServerRelayConnection()
            self.establishClientRelayConnection()
            self.handle_one_request()

    def processMessage(self):
        if not self.bTunneling:
            with self.handleProxyError():
                # Connect to destination
                self.establishServerRelayConnection()
        sBody = self.rfile.read(int(self.headers['Content-Length'])) if 'Content-Length' in self.headers else None
        oHttpReqWrapper = HTTPRequestWrapper(self.requestline, self.headers, sBody)

        self.oClientServerRelay.relay(oHttpReqWrapper.encode())

        # Parse response
        oHttpResponseWrapper = self.oClientServerRelay.getServerResponse(self.request_version)
        self.oClientServerRelay.disconnect()

        # Relay the message
        oCensorshipEngine.process(oHttpResponseWrapper.getDecodedBody())
        self.request.sendall(bytes(oHttpResponseWrapper))


    # Forward all other messages to the message processor. 
    do_GET = processMessage
    do_POST = processMessage
    do_HEAD = processMessage
    do_PUT =  processMessage
    do_DELETE =  processMessage
    do_TRACE = processMessage
    do_PATCH =  processMessage


class ProxyServer(ThreadingMixIn, HTTPServer):

    def __init__(self, server_address=('127.0.0.1', 8080), RequestHandlerClass=ProxyMessageHandler):
        HTTPServer.__init__(self, server_address, RequestHandlerClass)


if __name__ == '__main__':
    # TODO: Figure out how to cleanly make the censorship engine and auth manager avalialbe to the ProxyMessageHandler.
    oCensorshipEngine = CensorshipEngine()
    oProxyServer = ProxyServer()
    oParser = argparse.ArgumentParser(description="Proxy server with build in censorship engine.")
    oParser.add_argument('-a', '--authstore', help='Path to the auth store (the auth folder)', required=True)
    oArgs = vars(oParser.parse_args())
    if not os.path.exists(oArgs.get('authstore')):
        print("{0} does not exist.".format(oArgs.get('authstore')))
        sys.exit(-1)
    sAuthStore = oArgs.get('authstore')
    oCA = CA(sKeyPath=os.path.join(sAuthStore, 'fakeCA.key'), sCrtPath=os.path.join(sAuthStore,'fakeCA.crt'))
    oAuthManager = AuthenticationManager(oCA, sAuthStore, os.path.join(sAuthStore, 'serv.key'))
    try:
        oProxyServer.serve_forever()
    finally:
        oProxyServer.server_close()

