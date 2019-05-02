############################
#                          #
# Author: Christian Seely  #
#                          #
############################
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

# The logger needs to be configured immediatly. 
logging.basicConfig(filename='censor.log', filemode='w', format='%(asctime)s - %(message)s', datefmt='%d-%b-%y %H:%M:%S', level=logging.INFO)

class CensorshipEngine(object):
    """
        Censorship engine responsible for enforcing configurable censorship rules. 
    """
    def __init__(self, aRules):
        """
          :param aRules: List of the rules to follow.
        """
        self.aRules = aRules

    def process(self, sClient, bBody):
        """
            Entry point for tasking the engine. 
            :param sClient: Client we are performing censorship on. 
            :param bBody: Decrypted/decoded content body of an http response. 
        """
        if bBody:
            # For each rule check if the content body of the page matches any of 
            # the censorship conditions. If it does then perform the actions for
            # that set of censorship conditions.
            for oRule in self.aRules:
                if oRule.matches(bBody):
                    sResult = oRule.performActions({'sClient' : sClient, 'bBody': bBody})
                    # If the action modifies the pages content body return it.
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
    """
        Supported actions.
    """
    LOG = 'Log' # Log the offence to the censorship log file.
    BLOCK = 'Block' # Block the web page from the user.
    EDIT = 'Edit' # Edit the contents of the page.

class CONDITION_TYPES(object):
    REGEX = 'Regex' # Regex match
    CLASSIFY = 'Classify' # NL document classification type match.

class Action(ABC):
    """
        Action base class.
    """
    @abstractmethod
    def perform(**kwargs):
        pass

class LogAction(Action):
    """
        Class that handles logging censorship violations.
    """
    def __init__(self, oSettings, aRequiredArgs):
        """
            :param oSettings: Settings for the action from the config file.
            :param aRequiredArgs: The arguments required to run the perform method.
        """
        self.aRequiredArgs = aRequiredArgs

    def perform(self, sClient):
        """
            :param sClient: IP address of the client we are monitoring.
        """
        logging.info("Client: {0} as violated censorship rules.".format(str(sClient)))

class BlockAction(Action):
    """
        Class that handles blocking web pages that violate censorship conditions.
    """
    def __init__(self, oSettings, aRequiredArgs):
        """
            :param oSettings: Settings for the action from the config file.
            :param aRequiredArgs: The arguments required to run the perform method.
        """
        self.aRequiredArgs = aRequiredArgs
        # Define the block page.
        self.sBlockPage = """
            <!DOCTYPE html>
            <html>
            <body>
            <h1>{0}</h1>
            </body>
            </html>
        """.format(oSettings.get('BlockMessage'))

    def perform(self):
        """
            :return: The block page.
        """
        return self.sBlockPage

class EditAction(Action):
    """
        Class that handles modifying the content body of web pages before returning them.
    """
    def __init__(self, oSettings, aRequiredArgs):
        """
            :param oSettings: Settings for the action from the config file.
            :param aRequiredArgs: The arguments required to run the perform method.
        """
        self.aRequiredArgs = aRequiredArgs
        # Precompile the regex statement from the config file.
        self.oRegex = re.compile(oSettings.get('Start'))
        self.sReplacement = oSettings.get('End')

    def perform(self, bBody):
        """
            :param bBody: The content body of the web page.
            :return: Return the modifed content body of the web page.
        """
        return self.oRegex.sub(self.sReplacement, bBody.decode('utf-8'))

class Condition(ABC):
    """
        Abstract class for conditions.
    """
    def matches(**kwargs):
        pass

class RegexCondition(Condition):
    """
        Condition class checking performing regex searches in the content bodies of 
        web pages.
    """
    def __init__(self, oSettings):
        """
            :param oSettings: Settings for the condition from the config file.
        """
        # Precompile the regex expression.
        self.oRegex = re.compile(oSettings.get('Pattern'))

    def matches(self, bBody):
        """
            :param bBody: The content body of the web pages.
            :return: True if the regex search matched on something, False otherwise.
        """
        return self.oRegex.search(bBody.decode('utf-8'))

class ClassifyCondition(Condition):
    """
        Condition class for checking if the content of a web pages violates
        a blacklisted category defined by the users. (Categories must coincide with Google Clouds NL's
        document classifications)
    """
    def __init__(self, oSettings):
        # To use this feature the user must specify their google application 
        # credentials file.
        assert('GOOGLE_APPLICATION_CREDENTIALS' in os.environ)
        # Only import if the user is using this feature.
        from google.cloud import language
        # Instantiate the language client.
        self.oLanguageClient = language.LanguageServiceClient()
        self.aCategories = oSettings.get('Categories')

    def matches(self, bBody):
        # Use the heuristic mentioned in some of the research papers reviews
        # on HTML document classification. The classification technique is using 
        # the contents between the title tags which usually coincides with the 
        # actual content of the page. Additionally, this drastically increases 
        # the performance compared to trying to classify the document using 
        # the entire content of the document. The only caveat is the accuracy
        # of the classification is lowered. This tradeoff is worth it however.
        try:
            sTitle = bBody.decode('utf-8').split('<title>')[1].split('</title>')[0]
        except Exception as e:
            try: # The tag may be in upper case.
                sTitle = bBody.decode('utf-8').split('<TITLE>')[1].split('</TITLE>')[0]
            except Exception as e:
                # If the page doesn't follow the HTML standard just return.
                return
        # Ensure there is at least 20 words. (Required for classifcation).
        aTmp = sTitle.split()
        iNWords = len(aTmp)
        if iNWords < 1:
            return
        elif iNWords < 20:
            sTitle = ' '.join(sWord for sWord in aTmp * (math.ceil((20 - iNWords) / iNWords) + 1))
        # Perform the classification using one of Googles pre-trained classification models.
        # The classification is done remotlely in a distributed fashon on Google clouds servers 
        # which either have top of the line GPU's or Googles custom designed TPU's (Tensor Processor Units). 
        # Offloading the work enables almost real time classification which would be difficult to do 
        # locally without lots of computing power.
        oDocument = language.types.Document(content=sTitle,type=language.enums.Document.Type.PLAIN_TEXT)
        oResponse = self.oLanguageClient.classify_text(oDocument)
        # Check what categories the document was classfied into if any.
        aFoundCategories = [oCategory.name for oCategory in oResponse.categories]
        # Check if the found category matches any of our black listed ones.
        return any(sCategory in aFoundCategories for sCategory in self.aCategories)

class Rule(object):
    """
        A rule mapping of a set of conditions to a
        set of actions. When one condition in the condition
        set is matched all actions in the action set are performed.
    """
    def __init__(self, aConditions, aActions):
        """
            :param aConditions: List of conditions.
            :param aActions: List of actions.
        """
        self.aConditions = aConditions
        self.aActions = aActions

    def matches(self, bBody):
        """
            :param bBody: The content body of the html page.
            :return: True if any of the conditions in the condition set match.
        """
        return any(oCondition.matches(bBody) for oCondition in self.aConditions)

    def performActions(self, oArgPool):
        """
            :param oArgPool: Pool of arguments the specific argument classes can pull from.
            :return: Modifed content body of the html page. (If there is one).
        """
        # Iterate over each action and pass the request arguments to it.
        for oAction in self.aActions:
            sResult = oAction.perform(*(oArgPool.get(sArg) for sArg in oAction.aRequiredArgs))
            # For actions that modify the content body.
            if sResult:
                return sResult

class Parser(object):
    """
        Class for parsing the censorship config file.
    """
    @staticmethod
    def parseCensorshipConf(sPath):
        """
            Note: To make things easier I'm assuming the user will
            provide a valid config file.
        
            :param sPath: Path to the censorship config file
            :return: A list of censorship rules.
        """
        try:
            with open('censorConf.json', 'rb') as oJson:
                oJsonCont = json.loads(oJson.read())
            return list(map(Parser.ruleFactory, oJsonCont.get('Settings')))
        except Exception as e:
            raise Exception("Unable to parse config file. {0}".format(str(e)))

    @staticmethod
    def ruleFactory(oJsonRule):
        """
            :param oJsonRule: A JSON object containing the settings for a singular rule.
            :return: The Rule instance.
        """
        aConditions = []
        aActions = []
        # Create the conditions for the rule.
        for sCond, oSettings in oJsonRule.get('Conditions').items():
            if sCond == CONDITION_TYPES.REGEX:
                aConditions.append(RegexCondition(oSettings))
            if sCond == CONDITION_TYPES.CLASSIFY:
                aConditions.append(ClassifyCondition(oSettings))
        # Create the actions for the rule.
        for sAction, oSettings in oJsonRule.get('Actions').items():
            if sAction == ACTION_TYPES.LOG:
                aActions.append(LogAction(oSettings, ['sClient']))
            if sAction == ACTION_TYPES.BLOCK:
                aActions.append(BlockAction(oSettings, []))
            if sAction == ACTION_TYPES.EDIT:
                aActions.append(EditAction(oSettings, ['bBody']))
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
        os.system(sCmd) # Using os.system because for some reason the subprocess module is losing paths.
        time.sleep(5) # Simulate blocking for previous command, ideally would be better to explicitly block.

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
    """
        Supported html body content encodings.
    """
    GZIP = 'gzip' # The content bodies containing html are usually compressed with gzip.

class CONTENT_TYPES(object):
    """
        Supported document types.
    """
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
        except Exception as e:  
            # If something goes wrong display the error on the browser (not something to do in production).
            self.send_error(418, str(e)) 
            

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
        sResult = oCensorshipEngine.process(self.client_address, oHttpResponseWrapper.getDecodedBody())
        # The engine might end up modifying the content of the body. If that's the case 
        # we need to reencode it before forwarding it to the client.
        # Forward the reponse to the client. 
        if sResult:
            self.request.sendall(bytes(sResult.encode('utf-8')))
        else:
            self.request.sendall(bytes(oHttpResponseWrapper))

    # So the HTTPServer won't spam stdout with log messages.
    def log_message(self, format, *args):
        return

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
    oParser = argparse.ArgumentParser(description="Proxy server with build in censorship engine.")
    oParser.add_argument('-a', '--authstore', help='Path to the auth store (the auth folder)', required=True)
    oParser.add_argument('-c', '--censorconf', help='Path to the censorship config file', required=True)
    oArgs = vars(oParser.parse_args())
    sAuthStore = oArgs.get('authstore')
    sCensorConfPath = oArgs.get('authstore')
    if not os.path.exists(sAuthStore):
        print("{0} does not exist.".format(sAuthStore))
        sys.exit(-1)
    if not os.path.exists(sCensorConfPath):
        print("{0} does not exist.".format(sCensorConfPath))
        sys.exit(-1)
    oCensorshipEngine = CensorshipEngine(Parser.parseCensorshipConf(sCensorConfPath))
    oProxyServer = ProxyServer()
    oCA = CA(sKeyPath=os.path.join(sAuthStore, 'fakeCA.key'), sCrtPath=os.path.join(sAuthStore,'fakeCA.crt'))
    oAuthManager = AuthenticationManager(oCA, sAuthStore, os.path.join(sAuthStore, 'serv.key'))
    try:
        oProxyServer.serve_forever()
    finally:
        oProxyServer.server_close()

