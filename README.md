# A practical security guide for web developers

### The intended audience

Security issues happen for two reasons - 

1. Developers who have just started and cannot really tell a difference between using MD5 or bcrypt.
2. Developers who know stuff but forget/ignore them.

Our detailed explainations should help the first type while we hope our checklist helps the second one create more secure systems. This is by no means a comprehensive guide, it just covers stuff based on the most common issues we have discovered in the past.


### Contents

1. [The Security Checklist](#the-security-checklist)
2. What can go wrong?
3. Securely transporting stuff: HTTPS explained
4. I am who I say I am: Authentication  
4.1 Form based authentication  
4.2 Basic authentication  
4.3 One is not enough, 2 factor, 3 factor, ....   
4.4 Why use insecure text messages? Introducing HOTP & TOTP   
4.5 Handling password resets
5. What am I allowed to do?: Authorization  
5.1 Token based Authorization  
5.2 OAuth & OAuth2  
5.3 JWT
6. Trust no one: User Inputs are evil  
6.1 Sanitizing Inputs  
6.2 Sanitizing Outputs  
6.3 Cross Site Scripting  
6.4 Injection Attacks  
6.5 User uploads  
6.6 Tamper-proof user inputs
7. Plaintext != Encoding != Encryption != Hashing  
7.1 Common encoding schemes  
7.2 Encyption  
7.3 Hashing & One way functions  
7.4 Hashing speeds cheatsheet
8. dadada, 123456, cute@123: Passwords  
8.1 Password policies  
8.2 Storing passwords  
8.3 Life without passwords
9. Public Key Cryptography
10. Remember me, please: Handling Sessions  
10.1 Where to save state?  
10.2 Invalidating sessions  
10.3 Cookie monster & you
11. Fixing security, one header at a time  
11.1 Secure web headers  
11.2 Data integrity check for 3rd party code  
11.3 Certificate Pinning
12. Configuration mistakes    
12.0 Provisoning in cloud: Ports, Shodan & AWS   
12.1 Honey, you left the debug mode on  
12.2 Logging (or not logging)  
12.3 Monitoring  
12.4 Principle of least privilege  
12.5 Rate limiting & Captchas  
12.6 Storing project secrets and passwords in a file    
12.7 DNS: Of subdomains and forgotten pet-projects  
12.7 Patching & Updates  
13. When the bad guys arrive: Attacks  
13.1 Clickjacking  
13.2 Cross Site Request Forgery  
13.3 Denial of Service  
13.4 Server Side Request Forgery
14. [Stats about vulnerabilities discovered in Internet Companies](vulnerabilities-stats.md)   
15. On reinventing the wheel, and making it square  
15.1 Security libraries and packages for Python  
15.2 Security libraries and packages for Node/JS  
15.3 Learning resources
16. Maintaining a good security hygiene
17. Security Vs Usability
18. Back to Square 1: The Security Checklist explained

### The Security Checklist 

##### AUTHENTICATION SYSTEMS (Signup/Signin/2 Factor/Password reset) 
- [ ] Use HTTPS everywhere.
- [ ] Store password hashes using `Bcrypt` with a random `salt`.
- [ ] Destroy the session identifier after `logout`.  
- [ ] Destory all active sessions on reset password (or offer to).  
- [ ] Must have the `state` parameter in OAuth2
- [ ] No open redirects after successful login or in any other intermediate redirects.
- [ ] While Signup/Login input, sanitize input for javascript://, data://, CRLF characters. 
- [ ] Set secure, httpOnly cookies.
- [ ] In Mobile `OTP` based mobile verification, do not send the OTP back in the response when `generate OTP` or `Resend OTP`  API is called.
- [ ] Limit attempts to `Login`, `Verify OTP`, `Resend OTP` and `generate OTP` APIs for a particular user. Have an exponential backoff set or/and something like a captcha based challenge.
- [ ] Check for randomness of reset password token in the emailed link or SMS 
- [ ] Set an expiration on the reset password token for a reasonable period.
- [ ] Expire the reset token after it has been successfully used.
- [ ] Destroy the logged in user's session everywhere after successful reset of password. 


##### USER DATA & AUTHORIZATION
- [ ] Any resource access like, `my cart`, `my history` should check the logged in user's ownership of the resource using session id.
- [ ] Serially iterable resource id should be avoided. Use `/me/orders` instead of `/user/37153/orders`. This acts as a sanity check in case you forgot to check for authorization token. 
- [ ] `Edit email/phone number` feature should be accompanied by a verification email to the owner of the account. 
- [ ] Any upload feature should sanitize the filename provided by the user. Also, for generally reasons apart from security, upload to something like S3 (and post-process using lambda) and not your own server capable of executing code.  
- [ ] `Profile photo upload` feature should sanitize all the `EXIF` tags also if not required.
- [ ] For user ids and other ids, use [RFC complaint ](http://www.ietf.org/rfc/rfc4122.txt) `UUID` instead of integers. You can find an implementation for this for your language on Github.  
- [ ] JWT are awesome, use them if required for your single page app/APIs.


##### ANDRIOD / IOS APP
- [ ] `salt` from payment gateways should not be hardcoded.
- [ ] `secret` / `auth token` from 3rd party SDK's should not be hardcoded.
- [ ] API calls intended to be done `server to server` should not be done from the App.
- [ ] In Android, all the granted  [permissions](https://developer.android.com/guide/topics/security/permissions.html) should be carefully evaluated.
- [ ] [Certificate pinning](https://en.wikipedia.org/wiki/HTTP_Public_Key_Pinning) is highly recommended.


##### SECURITY HEADERS & CONFIGURATIONS
- [ ] `Add` [CSP](https://en.wikipedia.org/wiki/Content_Security_Policy) header to mitigate XSS and data injection attacks. This is important.
- [ ] `Add` [CSRF](https://en.wikipedia.org/wiki/Cross-site_request_forgery) header to prevent cross site request forgery.
- [ ] `Add` [HSTS](https://en.wikipedia.org/wiki/HTTP_Strict_Transport_Security) header to prevent SSL stripping attack.
- [ ] `Add` [X-Frame-Options](https://en.wikipedia.org/wiki/Clickjacking#X-Frame-Options) to protect against Clickjacking.
- [ ] `Add` [X-XSS-Protection](https://www.owasp.org/index.php/OWASP_Secure_Headers_Project#X-XSS-Protection) header to mitigate XSS attacks.
- [ ] Update DNS records to add [SPF](https://en.wikipedia.org/wiki/Sender_Policy_Framework) record to mitigate spam and phishing attacks.
- [ ] Add [subresource integrity checks](https://en.wikipedia.org/wiki/Subresource_Integrity) if loading your JavaScript libraries from a third party CDN.
- [ ] Use random CSRF tokens and expose buisness logic APIs as HTTP POST requests. Do not expose CSRF tokens over HTTP for example in a inital request upgrade phase.
- [ ] Do not use critical data or tokens in GET request parameters. Exposure of server logs or a machine/stack processing them would expose user data in turn.

##### SANITIZATION OF INPUT
- [ ] `Sanitize` all user inputs or any input parameters exposed to user to prevent [XSS](https://en.wikipedia.org/wiki/Cross-site_scripting)
- [ ] `Sanitize` all user inputs or any input parameters exposed to user to prevent [SQL Injection](https://en.wikipedia.org/wiki/SQL_injection)
- [ ] Sanitize user input if using it directly for functionalites like CSV import.
- [ ] `Sanitize` user input for special cases like robots.txt as profile names in case you are using a url pattern like coolcorp.io/username. 
- [ ] Do not hand code or build JSON by string concatentation ever, no matter how small the object is. Use your langauge defined libraries or framework.
- [ ] Sanitize inputs that take some sort of URLs to prevent [SSRF](https://docs.google.com/document/d/1v1TkWZtrhzRLy0bYXBcdLUedXGb9njTNIJXa3u9akHM/edit#heading=h.t4tsk5ixehdd).
- [ ] Sanitize Outputs before displaying to users.

##### OPERATIONS
- [ ] If you are small and inexperienced, evaluate using AWS elasticbeanstalk or a PaaS to run your code.
- [ ] Use a decent provisioning script to create VMs in the cloud.
- [ ] Check for machines with unwanted publicly `open ports`.
- [ ] Check for no/default passwords for `databases` especially MongoDB & Redis. BTW MongoDB sucks, avoid it.
- [ ] Use SSH to access your machines, do not setup a password.
- [ ] Install updates timely to act upon zero day vulnerabilities like Heartbleed, Shellshock.
- [ ] Modify server config to use TLS 1.2 for HTTPS and disable all other schemes. (The tradeoff is good)
- [ ] Do not leave the DEBUG mode on. In some frameworks, DEBUG mode can give access full-fledged REPL or shells or expose critical data in error messages stacktraces.
- [ ] Be prepared for bad actors & DDOS - use [Cloudflare](https://www.cloudflare.com/ddos/)
- [ ] Setup monitoring for your systems and log stuff (use Newrelic or something like that)
- [ ] If developing for enterprise customers, adhere to compliance requirements. If AWS S3, consider using the feature to [encrypt data](http://docs.aws.amazon.com/AmazonS3/latest/dev/UsingServerSideEncryption.html). If using AWS EC2, consider using the feature to use encrypted volumes (even boot volumes can be encypted now). 

##### PEOPLE
- [ ] Setup an email (e.g. security@coolcorp.io) and a page for security researchers to report vulnerabilities.
- [ ] Depending on what you are making, limit access to your user databases.
- [ ] Be polite to bug reporters.
- [ ] Have your code review done by a fellow developer from a secure coding perspective. (More eyes)
- [ ] In case of a hack or data breach, check previous logs for data access, ask people to change passwords. You might require an audit by external agencies depending on where you are incorporated.  
- [ ] Setup Netflix Scumblr to hear about talks about your organization on social platforms and Google search.

### Who are we?

We are full stack developers who just grew tired by watching how developers were lowering the barrier to call something a hack by writing unsecure code. In the past six months we have prevented leaks of more than 15 million credit card details, personal details of over 45 million users and potentially saved companies from shutting down. Recently, we discovered an issue that could result in system takeover and data leak in a bitcoin institution. We have helped several startups secure their systems, most of them for free, sometimes without even getting a thank you in response :)


*If you disagree with something or find a bug please open an issue or file a PR. Alternatively, you can talk to us on hello@fallible.co*
