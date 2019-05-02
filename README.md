# DPI_Censorship_Engine

### Author: Christian Seely

High level overview of bigBrotherProxy.py (see comments in code for more details):
The big brother proxy is a proxy server that performs SSL interception to pull out the unencrypted contents of requests/responses between a client and an external web server. The unencrypted contents are passed to a configurable censorship engine that performs various types of censorship based on what is defined in the censorship config files.

Relevant Censorship Terminology: 
Condition: A condition is a type of censorship check that will return true when satisfied. 

Action: An action is what is done when a condition returns true.

Rule: A rule is a mapping of a set of conditions to a set of actions. If any condition in
the condition set is satisfied then all actions in the action set are performed. Rules used to
parameterize the censorship engine at startup.

Censorship config files (See censorConfExOne.json and censorConfExTwo.json for usable examples):
At the top level of the file is a single field "Settings" which is mapped to a list of censorship rules represented
as JSON objects. Each rule has two fields "Conditions" and "Actions" both of which map to JSON objects where supported
conditions and actions can be specified along with their settings.

Supported Conditions include:
Regex: Performs regex search on html pages.
Classify: Performs NL document classification on portions of html pages.

Supported Actions include:
Log: Log the offense to the censorship log.
Edit: Edit the contents of the page.
Block: Block the web page from the user.

Requirements (some are temporary):
* Python 3.5+
* Linux (only tested on Ubuntu Desktop 17.10 and 18.04) 
* OpenSSL must be installed (only tested using OpenSSL 1.0.2g)
* The pre-generated certificates/keys (included in the auth folder)

Classifier Mode Requirements:
* To perform classification you MUST have a Google Cloud account with credits. (Free credits for student accounts)
* Set the GOOGLE_APPLICATION_CREDENTIALS environmental variable to point to your credential’s files.
* Create a virtual environment with Python 3
* Activate the virtual environment
* Next install the required libraries by running `pip install -r requirements.txt`

Note on Supported Sites: This program does not support every website as web servers/browsers can be finicky and there is too much variation. It appears that around half of sites tested appease both the web server and the browser. With that being said, the purpose is of this program is to explore censorship techniques not to create a commercial product. Also note that some sites take a long time to load because they pull in so many static files. (i.e The New York Times) The following sites tested and work:


Sites:
* https://www.york.ac.uk/teaching/cws/wws/webpage1.html
* https://en.wikipedia.org/wiki/Barack_Obama
* https://en.wikipedia.org/wiki/United_States_Senate
* https://en.wikipedia.org/wiki/Academic_Ranking_of_World_Universities
* https://en.wikipedia.org/wiki/Duck


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
* As mentioned above not every browser and site is supported.

Script usage:
```
usage: bigBrotherProxy.py [-h] -a AUTHSTORE -c CENSORCONF

Proxy server with build in censorship engine.

optional arguments:
  -h, --help            show this help message and exit
  -a AUTHSTORE, --authstore AUTHSTORE
                        Path to the auth store (the auth folder)
  -c CENSORCONF, --censorconf CENSORCONF
                        Path to the censorship config file 
```

Once the script is run try navigating to one of the two sites listed above. When visiting the site please make sure your cache is cleared, this just insures that the browser does not have the sites contents cached which would prevent it from going through the proxy. 


Since setting things up can be slightly a hassle I included a couple short videos demoing the current functionality:

Scenario One:
- Condition: Regex match on "creative"
- Action: Log the offense.

Scenario Two:
- Condition: Regex match on "Harvard University"
- Action: Replace "Harvard University" with "University of New Mexico"

Scenario Three:
- Condition: Classfier matches on "/News/Politics", "/Law & Government/Government"
- Action: Block the page.
