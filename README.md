# DVWA
This project tests on the DVWA website 

## Setup
To setup DVWA, follow the following website:
https://nooblinux.com/how-to-install-dvwa/

## Brute Force Password
### Low and Medium
To run a brute force search on DVWA, burp suite is used. Burp suite is used to intercept the requests that are sent to the DVWA website. 
To setup:
1. Go to Proxy -> Options - Note the IP address and Port
2. Go to Intercept - Make sure that the intercept is on

Within a browser: 
1. Go to Network settings and set proxy address and the port to the noted down IP address and port number.
2. Set allow intercept in about:config for network.proxy to be true.


#### (Option 1) Run Hydra (a brute force tool):
1. Run the following command: hydra <DVWA Ip address> -l admin -P /usr/share/set/src/fasttrack/wordlist.txt http-get-form "/dvwa/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:Username and/or password incorrect.:H=Cookie: security=Low; PHPSESSIONID=eogppved743ckngeo0so6tnp87"
 Command Detaials:
 * -l - Username
 * -P - file that consists of frequently used passwords 
 * -http-get-form - tells hydra to get use a GET request form to submit the details
 * username=^USER^&password=^PASS^ - Places for the custom username and password
 * :F= - Faliure Message
 * :H= - Cookie information

 #### (Option 2) Run BurpSuite:
 1. After incepting the traffic, right click on the captured data and send to intruder
 2. In the intruder tab, under positions, change the attack type to ```Cluster bomb```
 3. Click the ![image](https://user-images.githubusercontent.com/39514108/145332448-36683182-a233-4ef9-8259-817eccc8e886.png) sign. Then ![image](https://user-images.githubusercontent.com/39514108/145332475-ff1a7c9a-006d-42e6-b12e-3fc8fff25015.png) for the username and password fields like below:
 ![image](https://user-images.githubusercontent.com/39514108/145332493-f3066fb7-64ea-4b59-ad9b-6517067aab38.png)
4. Within the payloads tab, insert the wordlist for the username in Payload set 1, and the wordlist for the password in Payload set 2. After starting the attack, the following is observed. Note that the lenght difference indicates that it was a successful attack. 
 ![image](https://user-images.githubusercontent.com/39514108/145332329-9ce1c01a-833d-426a-a5bb-de345bc01050.png)
 
 ### High
 
 The CSRF token is required to login. Hence, setting the user_token field found after inspecting the page, to be recursive grep where the token is constantly changed helps to brute force the search. The offset is taken from the point at which the user_token field is indicated (If the DOC is not found, resend a new request to the intruder).
![image](https://user-images.githubusercontent.com/39514108/145777006-d7a501ad-be0b-4df7-9f77-3e8a53da1151.png)
 1. Set the attack type to be pitchfork (sets the payloads in order) and the password and user_token to be custom variables.
 2. Load the list.
 3. Set the grep match to be incorrect ![image](https://user-images.githubusercontent.com/39514108/145777551-b2c72985-24a0-4551-ab1c-ed8f75e88067.png)
 4. Set the redirections to be always. ![image](https://user-images.githubusercontent.com/39514108/145777626-39f44f9c-23b5-43de-98a1-1fac22bff62c.png)
 5. Set the second payload (user_token) to eb recursive grep to allow the user_token to be trialed.
 6. Set the resource pool to have 1 concurrent thread
 
 After running the attack, the username and password with the CSRF token is found. 
 ![image](https://user-images.githubusercontent.com/39514108/145777913-2cd3c865-e74f-48b0-b08b-a675e03b0231.png)
 From this, we can see the CSRF token is used from the previous session. Hence, we can take the last request and paste that as the CSRF token in our browser. After using the username: admin and password: password, the login is done:
 ![image](https://user-images.githubusercontent.com/39514108/145778633-52922bd6-f8ee-4e7b-bdaa-041da66ab331.png)
 
 ### Brute force Remarks
 
 To make the page secure, enforce password policies and maximum attempts on the password. Extra security features such as enabling 2MFA is also recommended.




 
