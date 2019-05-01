import os
import time
import gzip
import zlib
import subprocess
import argparse
import json
import re
import math
import logging
from contextlib import contextmanager
from abc import ABC, abstractmethod
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from http.client import HTTPResponse
from ssl import wrap_socket
from socket import socket
from google.cloud import language

class CensorshipEngine(object):
    """
        Censorship engine providing both in line (blocking) and off-line Deep packet inspection (DPI).
    """
    def __init__(self, aRules):
        self.aRules = aRules

    def process(self, bBody):
        """
            Entry point for tasking the engine. 
            :param bBody: Decrypted/decoded content body of an http response. 
        """
        # Just print out the content body for now to show the ssl-interception is working. 
        if bBody:
            print(bBody)
        for oRule in self.aRules:
            if oRule.matches(bBody):
                sResult = oRule.performActions()
                if sResult:
                    return sResult
class CA(object):
    """
        Representation of our fake Certificate Authority
    """
    def __init__(self, sKeyPath, sCrtPath):
        """
            :param sKeyPath: Root key path.
            :param sCrtPath: Root certificate path. 
        """
        self.sKeyPath = sKeyPath
        self.sCrtPath = sCrtPath

    def sign(self, sServerCrs):
        """
            Using openssl generate the CA signed certificate for the connection.
            
            :param sServerCrs: Path to the generated server certificate signing request.
            :return: Command to generate the CA signed certificate.
        """
        return "openssl x509 -req -in {0} -CA {1} -CAkey {2} -CAcreateserial".format(sServerCrs, self.sCrtPath, self.sKeyPath) 

class ACTION_TYPES(object):
    LOG = 'Log'
    BLOCK = 'Block'
    EDIT = 'Edit'

class CONDITION_TYPES(object):
    REGEX = 'Regex'
    CLASSIFY = 'Classify'

class Action(ABC):
    @abstractmethod
    def perform(**kwargs):
        pass

class LogAction(Action):

    def __init__(self, oSettings):
        sOutPutDir = oSettings.get('OutputDir')
        if not os.path.exists(sOutPutDir):
            os.makedirs(sOutPutDir)
        sLogFile = os.path.join(sOutPutDir, oSettings.get('File'))
        logging.basicConfig(filename='app.log', filemode='w', format='%(asctime)s - %(message)s', datefmt='%d-%b-%y %H:%M:%S')

    def perform(self, sMessage):
        logging.info(sMessage)

class BlockAction(Action):

    def __init__(self, oSettings):
        self.sBlockPage = """
            <!DOCTYPE html>
            <html>
            <body>
            <h1>{0}</h1>
            </body>
            </html>
        """.format(oSettings.get('BlockMessage'))

    def perform(self):
        return self.sBlockPage

class EditAction(Action):

    def __init__(self, oSettings):
        self.oRegex = re.compile(oSettings.get('Start'))
        self.sReplacement = oSettings.get('End')

    def perform(self, sBody):
        return self.oRegex.sub(self.sReplacement, sBody)

class Condition(ABC):
    def matches(**kwargs):
        pass

class RegexCondition(Condition):

    def __init__(self, oSettings):
        self.oRegex = re.compile(oSettings.get('Pattern'))

    def matches(self, bBody):
        return self.oRegex.matches(bBody)

class ClassifyCondition(Condition):

    def __init__(self, oSettings):
        # Only import if the user is using this feature.
        from google.cloud import language
        self.aCategories = oSettings.get('Categories')

    def matches(self, bBody):
        # For performance only check the between the title tags.
        # If there is no title return.
        try:
            sTitle = bBody.split('<title>')[1].split('</title>')[0]
        except Exception as e:
            return
        # Ensure there is at least 20 words. (Required for classifcation).
        aTmp = sTitle.split()
        iNWords = len(aTmp)
        if iNWords < 1:
            return
        elif iNWords < 20:
            sTitle = ' '.join(sWord for sWord in aTmp * (math.ceil((20 - iNWords) / iNWords) + 1))

        # Perform the classification.
        oDocument = language.types.Document(content=sTitle,type=language.enums.Document.Type.PLAIN_TEXT)
        oResponse = language_client.classify_text(oDocument)
        aFoundCategories = oResponse.categories
        return any(sCategory in aFoundCategories for sCategory in self.aCategories)

class Rule(object):
    def __init__(self, aConditions, aActions):
        self.aConditions = aConditions
        self.aActions = aActions

    def matches(self):
        return any(oCondition.matches() for oCondition in self.aConditions)

    def performActions(self):
        for oAction in aActions:
            sResult = oAction.perform()
            # For actions that modify the content body.
            if sResult:
                return sResult

class Parser(object):
    @staticmethod
    def parseCensorshipConf(sPath):
        # try:
        with open('censorConf.json', 'rb') as oJson:
            oJsonCont = json.loads(oJson.read())
        return list(map(Parser.ruleFactory, oJsonCont.get('Settings')))
        # except Exception as e:
        #     raise Exception("Unable to parse config file. {0}".format(str(e)))

    @staticmethod
    def ruleFactory(oJsonRule):
        aConditions = []
        aActions = []
        for sCond, oSettings in oJsonRule.get('Conditions').items():
            if sCond == CONDITION_TYPES.REGEX:
                aConditions.append(RegexCondition(oSettings))
            if sCond == CONDITION_TYPES.CLASSIFY:
                aConditions.append(ClassifyCondition(oSettings))
        for sAction, oSettings in oJsonRule.get('Actions').items():
            if sAction == ACTION_TYPES.LOG:
                aActions.append(LogAction(oSettings))
            if sAction == ACTION_TYPES.BLOCK:
                aActions.append(BlockAction(oSettings))
            if sAction == ACTION_TYPES.EDIT:
                aActions.append(EditAction(oSettings))
        return Rule(aConditions, aActions)


class AuthenticationManager(object):
    """
        Class responsible for managing connection authentication. 
    """
    def __init__(self, oCA, sAuthStorePath, sServPKey):
        """
            :param oCA: The fake root CA.
            :param sAuthStorePath: Path to the auth 'store'
            :param sServPKey: Path to the servers private key.
            :param sServPKey: Path to the servers private key.
        """
        self.oCA = oCA
        self.sAuthStorePath = sAuthStorePath
        # TODO: Should cache remain between runs?
        self.sCertCache = os.path.join(os.getcwd(), 'certCache')
        if not os.path.exists(self.sCertCache):
            os.mkdir(self.sCertCache)
        self.sServPKey = sServPKey
        
    def genCert(self, sHost, sCert):
        """
            Generate the certificate for the server. 
            Note, to make things faster, the same private key for the server is being used
            to sign all the certificates. (Don't do this in production). 
            
            :param sHost: The servers host name. 
            :param sCert: Output certificate file.
        """
        sServerCrs = os.path.join(self.sCertCache, '{0}.csr'.format(sHost))
        # Generate the servers certificate signing request
        sCsrGenCmd = "openssl req -new -sha256 -key {0} -subj '/CN={1}' -out {2}".format(self.sServPKey, sHost, sServerCrs)
        # Generate the CA signed certificate.
        sCASignCmd = self.oCA.sign(sServerCrs)
        # Firefox (I'm not sure about other browsers), requires the key and certificate to be in the same file
        # so concatenate (cat) them together. 
        sCmd = "{{ cat {0}; {1} && {2}; }} > {3}".format(self.sServPKey, sCsrGenCmd, sCASignCmd, sCert)
        os.system(sCmd) # TODO make this blocking for some reason the subprocess module is losing paths. 
        time.sleep(5) # Temporary until prior is blocking..

    def getCert(self, sHost):
        """
            To perform ssl interception we need to 'pretend' to the the server the client is trying
            to communicate. To do this we need to sent TLS connections both with the client and the server.
            In this case we are setting one up with the client meaning we need to generate a certificate
            for the domain we are pretending to be. 
            :param sHost: The servers host name. 
            :return: The path to the certificate. 
        """
        sCert = os.path.join(self.sCertCache , '{0}.crt'.format(sHost))
        # If the certificate doesn't exist in our cache generate it on the fly. 
        if not os.path.exists(sCert): 
            self.genCert(sHost, sCert)
        return sCert


class CONTENT_ENCODINGS(object):
    GZIP = 'gzip' # The content bodies containing html are usually compressed with gzip.

class CONTENT_TYPES(object):
    HTML = 'text/html'

class Relay(ABC):
    """
        Base class for a relay communication. 
    """
    @abstractmethod
    def relay(self, bData):
        pass

class ClientServerRelay(Relay):
    """
        Class for relaying information from the client to the server. 
    """
    def __init__(self, sHost, iPort):
        """
            :param sHost: Server host name
            :param iPort: Connection port. 
        """
        self.oSock = socket()
        self.iPort = iPort
        self.sHost = sHost

    def connect(self, iTimeout, bTLS):
        """
            Connect to the server. 
            :param iTimeout: Connection timeout. 
            :param bTLS: Should the connection use tls or not. 
        """
        self.oSock.settimeout(iTimeout)
        self.oSock.connect((self.sHost, self.iPort))
        if bTLS:
            self.oSock = wrap_socket(self.oSock)

    def disconnect(self):
        """
            Close the connection. 
        """
        self.oSock.close()

    def relay(self, bData):
        """
            Relay the binary data from the client to the server. 
            :param bData: The binary data (http request)
        """
        self.oSock.sendall(bData)

    def getServerResponse(self, sHttpVer):
        """
            Get the response from the server. 
            :param sHttpVer: Version of the http protocol we are using. 
            :return: Instance of the HTTPResponseWrapper
        """
        return HTTPResponseWrapper(self.oSock, sHttpVer)

class ServerClientRelay(object):
    """
        Class to represent the server to client connection relay. 
    """
    def __new__(cls, oSock, sCertPath):
        """
            :param oSock: Previous client communication socket instance.
            :param sCertPath: Path to the generated server certificate.
            :return: socket.socket instance now using tls.
        """
        return wrap_socket(oSock, server_side=True, certfile=sCertPath)

class HTTPResponseWrapper(object):
    """
        Class that adds some additional utilities to the build in HTTPResponse class. 
    """
    def __init__(self, oSock, sHttpVer):
        """
            :param oSock: Communication socket. 
            :param sHttpVer: Version of the http protocol we are using. 
        """
        self.oHTTPResponse = HTTPResponse(oSock)
        self.oHTTPResponse.begin()
        self.bBody = self.oHTTPResponse.read()
        self.bResponseLine = '{0} {1} {2}\r\n'.format(sHttpVer, self.oHTTPResponse.status, self.oHTTPResponse.reason).encode()
        self.bHeaders = self.oHTTPResponse.msg.as_bytes()
        self.sEncoding = self.oHTTPResponse.getheader('Content-Encoding')
        self.sContentType = self.oHTTPResponse.getheader('Content-Type')
        self.oHTTPResponse.close() 

    def __bytes__(self):
        """
            :return: Raw bytes of the http response. 
        """
        return self.bResponseLine + self.bHeaders + self.bBody

    def getDecodedBody(self):
        """
            :return: Decoded content body of the http response.
        """
        # Only gzip encoding and html content types are supported at the moment. 
        if self.sEncoding == CONTENT_ENCODINGS.GZIP and CONTENT_TYPES.HTML in self.sContentType:
            try:
                # Zlib lets us decompress the gzipped contents as stored bytes. 
                return zlib.decompress(self.bBody, 16+zlib.MAX_WBITS)
            except Exception as e:
                print("Error decompressing gzip contents {0}".format(str(e)))
               

class HTTPRequestWrapper(object):
    """
        Class to represent an http request. 
    """
    def __init__(self, sReqLine, sHeaders, sBody):
        """ 
            :param sReqLine: The request line of the request.
            :param sHeaders: The headers for the request. 
            :param sBody: The content body for the request (optional). 
        """
        self.sReqLine = sReqLine
        self.sHeaders = sHeaders
        self.sBody = sBody

    def __repr__(self):
        """
            :return: The http request
        """
        sReq = '{0}\r\n{1}\r\n'.format(self.sReqLine, self.sHeaders)
        if self.sBody:
            sReq += self.sBody
        return sReq
    
    def encode(self):
        """
            :return: utf-8 encoded request.
        """
        return str(self).encode()
            
class ProxyMessageHandler(BaseHTTPRequestHandler):
    """
        Class responsible for handling http requests, one per connection. 
    """
    def __init__(self, request, client_address, server):
        """
            :param request: socket.socket connection. 
            :param client_address: Address of the client.
            :param server: Server ref. 
        """
        # Flag for whether we are doing http tunneling or not. (We almost always are).
        # For our use case https connections are tunneled, http are not. 
        self.bTunneling = False 
        BaseHTTPRequestHandler.__init__(self, request, client_address, server)

    @contextmanager
    def handleProxyError(self):
        """
            Handle proxy errors. 
        """
        try:
            yield # Run the body of the context.
        except Exception as e:  # TODO Add custom exceptions.
            self.send_error(418, str(e)) # :)
            

    def establishServerRelayConnection(self):
        """
            Establish a connection to the server the client is trying to communicate with. (Relay connection.)
        """
        sHostname, sPort = self.path.split(':')
        # Create client server relay with tls. 
        self.oClientServerRelay = ClientServerRelay(sHostname, int(sPort))
        self.oClientServerRelay.connect(15, self.bTunneling)
        # Tell the client that we established the connection on their behalf. 
        self.send_response(200, 'Connection established')
        self.end_headers()

    def establishClientRelayConnection(self):
        """
            Establish a connection to the client that the server can respond to. 
        """
        # Change the parent classes socket.socket to use tls with the generated server certificate. 
        self.request = ServerClientRelay(self.request, oAuthManager.getCert(self.path.split(':')[0]))
        # Setup the tls connection. 
        self.setup()

    def do_CONNECT(self):
        """
            Since the client is going through a proxy (us), they are going to send us a
            CONNECT http command to setup the tunneled connection to the server. Rather than
            tunneling the connection we are going to perform a man in the middle attack using
            ssl interception. To do that we will establish tls connection with the server on the
            clients behalf, and a tls connection with the client on the servers behalf. 
            
            Note, these methods are called by the parent class. 
        """
        # Connect means we want to setup a tunnel through the proxy.
        self.bTunneling = True
        with self.handleProxyError():
            # Connect to destination first, (since we generate certs on the fly..)
            self.establishServerRelayConnection()
            self.establishClientRelayConnection()
            self.handle_one_request()

    def processMessage(self):
        """
            Handle, all other http command (i.e GET, POST..) and relay request/responses between
            the client/server. Additionally, offload the response bodies to our censorship engine. 
        """
        # If we don't have a connection established already we need to establish one. (i.e with http requests). 
        if not self.bTunneling:
            with self.handleProxyError():
                # Connect to destination
                self.establishServerRelayConnection()
        # Build the http request to relay to the server. 
        sBody = self.rfile.read(int(self.headers['Content-Length'])) if 'Content-Length' in self.headers else None
        oHttpReqWrapper = HTTPRequestWrapper(self.requestline, self.headers, sBody)
        # Relay the request to the server. 
        self.oClientServerRelay.relay(oHttpReqWrapper.encode())

        # Parse the http response. 
        oHttpResponseWrapper = self.oClientServerRelay.getServerResponse(self.request_version)
        self.oClientServerRelay.disconnect()

        # Pass the decoded content body of the response to our censorship engine. 
        sResult = oCensorshipEngine.process(oHttpResponseWrapper.getDecodedBody())
        # The engine might end up modifying the content of the body. If that's the case 
        # we need to reencode it before forwarding it to the client.
        # Forward the reponse to the client. 
        if oResult:
            self.request.sendall(bytes(zlib.compress(oResult, 16+zlib.MAX_WBITS)))
        else:
            self.request.sendall(bytes(oHttpResponseWrapper))


    # Forward all other messages to the message processor, note these are parent methods we
    # are overriding. 
    do_GET = processMessage
    do_POST = processMessage
    do_HEAD = processMessage
    do_PUT =  processMessage
    do_DELETE =  processMessage
    do_TRACE = processMessage
    do_PATCH =  processMessage


class ProxyServer(ThreadingMixIn, HTTPServer):
    """
        Multi-threaded proxy server (subclasses HTTPServer, ThreadingMixIn for multi-threading)
    """
    def __init__(self, server_address=('127.0.0.1', 8080), RequestHandlerClass=ProxyMessageHandler):
        HTTPServer.__init__(self, server_address, RequestHandlerClass)


if __name__ == '__main__':
    # TODO: Figure out how to cleanly make the censorship engine and auth manager available to the ProxyMessageHandler.
    oCensorshipEngine = CensorshipEngine()
    oProxyServer = ProxyServer()
    # TODO: Add rest of command line arguments. 
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

