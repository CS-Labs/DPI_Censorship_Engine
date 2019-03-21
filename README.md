# DPI_Censorship_Engine

### Author: Christian Seely

Note: You can also find this exact same README in my project repo: (https://github.com/CS-Labs/DPI_Censorship_Engine) which has the videos referenced below embedded in for easier viewing. 

High level overview of bigBrotherProxy.py (see comments in code for more details):
The big brother proxy is a proxy server that performs SSL interception to pull out the unencrypted contents of requests/responses between a client and an external web server. The unencrypted contents are passed to a parameterizable censorship engine that performs various types of censorship, such as offense logging and in line content modification. 

Requirements (some are temporary):
* Python 3.5+
* Linux (only tested on Ubuntu 17.10 at the moment) 
* OpenSSL must be installed (only tested using OpenSSL 1.0.2g)
* The pre-generated certificates/keys (included in the auth folder)
* Visit one of the following sites (only ones tested):
  * https://www.york.ac.uk/teaching/cws/wws/webpage1.html
  * https://en.wikipedia.org/wiki/Barack_Obama

Please note: 
I have not had time to test things on different systems/browsers/sites which is why I have the restrictions above. That setup is the only one I can guarantee to work. 
With that being said, other systems/browsers/sites very well might work. In the future I might look into putting Firefox in a docker container so it won’t matter where things are being run. 

Setup (Using Ubuntu and Firefox):

Setup system wide proxy:
* Open up network settings
* Click Network proxy
* Enter the address 127.0.0.1 and port 8080 for the HTTP/HTTPS proxies. 

![Setup-system-wide-proxy](https://github.com/CS-Labs/DPI_Censorship_Engine/blob/master/gifs/system_proxy_setup.gif)

Add the fake CA as a trusted one:
* Open Firefox preferences/options
* Search cert
* Click on View Certificates
* Click on the Auth tab
* Click on import
* Navigate to the trustedCert.pem file (in the auth folder) and import it.

![fake-ca-setup](https://github.com/CS-Labs/DPI_Censorship_Engine/blob/master/gifs/cert_setup.gif)

Bugs:
* Not all sites work at the moment, Firefox does not always like what I'm sending it. 
* There are a lot of low-level SSL exceptions that are occurring (the broken pipe errors). I believe this has something to do with closing the connection, but it doesn't seem to effect anything so it will probably be suppressed in the future. 
* I have a timing error that causes a variable to become undefined, this also doesn't seem to affect anything as far as I can tell however.
* There is issued with http messages.
* Curl does not work, I believe this is because curl is not sending the HTTP Connect request before the GET request which most browsers such as Firefox do. 

Script usage:
```
python bigBrotherProxy.py --help  
usage: bigBrotherProxy.py [-h] -a AUTHSTORE  

Proxy server with build in censorship engine.

optional arguments:
  -h, --help            show this help message and exit  
  -a AUTHSTORE, --authstore AUTHSTORE  
                        Path to the auth store (the auth folder)  
```

Once the script is run try navigating to one of the two sites listed above. When visiting the cite please make sure your cache is cleared, this just insures that the browser does not have the sites contents cached which would prevent it from going through the proxy. 


Since setting things up can be slightly a hassle I included a short video demoing the current functionality:

![demo](https://github.com/CS-Labs/DPI_Censorship_Engine/blob/master/gifs/current_demo.gif)