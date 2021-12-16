# DVWA
This project tests on the DVWA website 

## Setup
To setup DVWA, follow the following website:
https://nooblinux.com/how-to-install-dvwa/

## 1. Brute Force Password
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

## 2. Command Injection
### Low
 In the command injection page, where the source code is shown below, the developer did not sanitise the input. 
![image](https://user-images.githubusercontent.com/39514108/145917705-140a128a-10da-4c18-b483-dfd2a56a1376.png)
This means that strings can be taken as a command. This means that we can execute extra commands with the use of ```;```. For example after executing: ```;cat /etc/passwd``` which gets the password file, the passwords are found:
 ![image](https://user-images.githubusercontent.com/39514108/145918303-eac42787-9451-416f-a1e4-4b8a1764a576.png)
Note that the use of ```;``` means that the command will execute regardless of whether the command before it was successful.
 
 ### Medium
 Upon viewing the source code as shown below, the && and ; characters are replaced. We can counteract this by using & which also executes the command.
 ![image](https://user-images.githubusercontent.com/39514108/145918619-c2c76272-1d9b-4ea0-b17a-f807c9734a4e.png). For example, after executing: ```8.8.8.8&cat /etc/passwd``` the password file is also displayed. Note that:
 * & - asynchronous 
 * | - takes the ouput from the first command to the second command
 * || - executed after the first command if it doesn't have a exit status of 0
 * && - executed after the first command if it does have a exit status of 0

### High
 Again when viewing the source code as shown below, all strings that matched are replaced. 
 ![image](https://user-images.githubusercontent.com/39514108/145919178-edd5a0df-67fc-4640-89c2-695f7be2979e.png)
This means that the command of ```|| ``` can still be used. This is because the array will match on the first occurance, hence, the first ```|``` will still remain. Furthermore, since the array matches on ```| ``` (with a space at the end), a single pipe will still work. The following commands can be used to exploit the vulnerability:
 * |cat /etc/passwd
 * || cat /etc/passwd
 
 ### Remarks
 To fix the code:
 1. Validate user input - by checking whether they have entered a valid IP address (whether the input is a number and in the specified format.)
 2. Escape shell arguemtns - by calling the escapeshellarg() function
 3. Treat all user input as strings 
 
## 3. CSRF
 CSRF is an attack in which a user clicks on a link which sends a request on the behalf of the user to a trsuted site. In this example, this is where a change request is made by the user.
 
 ### Easy
 After submitting the password change, a link is created: http://localhost/DVWA-master/vulnerabilities/csrf/?password_new=new_password&password_conf=new_password&Change=Change#. This can be sent to the user which could be embedded in a website such that the user's password is changed. 
 
 ### Medium
 In this case, the site now validates where the request is coming from. For example, after executing the above url, the following is displayed:
 ![image](https://user-images.githubusercontent.com/39514108/146326082-8fb358aa-1005-40f2-903d-50122e0b88bb.png). After observing the requests, we can see that the referer is missing:
  ![image](https://user-images.githubusercontent.com/39514108/146326273-8cfbbd02-d337-401d-baa7-fe270ec598c5.png) 
 in comparison to ![image](https://user-images.githubusercontent.com/39514108/146326420-63f7d94e-0d00-4712-8e63-772d3e5252b3.png)
After embedding a script and executing it like so: ![image](https://user-images.githubusercontent.com/39514108/146328932-569c99a4-5882-4745-b687-da9282c8fb07.png)
 
, the password is not changed as the referrer is missing. So instead, reflective xss can be used. This is where the user can add in code in a function within the page to send requests (hence, the referrer will be the same). We can embed, the following in the stored xss page which will then change the password:
 
![image](https://user-images.githubusercontent.com/39514108/146330227-00b5b314-16aa-4b32-b13c-293ca730e31c.png)
 
 ![image](https://user-images.githubusercontent.com/39514108/146330296-a6ee5050-aadf-46e7-b1ca-5c79bf52ff8e.png)
 
We can also construct a request in burp suite that includes the referrer. 
 ![image](https://user-images.githubusercontent.com/39514108/146330940-ad126570-6773-45fb-ab2a-e14171451a40.png). After forwarding the request, the password is also changed.
 
 ### High
 After sending a request through to change the password we can see the following request being made, where an anti-CSRF token is added. 
 
 However, after inspecting the page, we see a hidden token that is attached to the page, ![image](https://user-images.githubusercontent.com/39514108/146333155-6acea507-a33e-4cdd-88ed-522c7cd9ffd4.png). 
 This means that we can create another request which incorporates the next value to send to the webpage. For example, by using the following link:
 http://localhost/DVWA-master/vulnerabilities/csrf/?password_new=janel&password_conf=janel&Change=Change&user_token=6c3e10f0fc44c8249e70ce243b4c9e96 (which the user token is gained after refreshing the page), the password is changed.
 
 ### Remarks
 
 To prevent CSRF attacks, same-site cookies or asking for the current user's password can be used. 

 


