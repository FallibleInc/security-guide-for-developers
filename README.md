# A practical security guide for web developers (Work in progress)

### The intended audience

Security issues happen for two reasons - 

1. Developers who have just started and cannot really tell a difference between using MD5 or bcrypt.
2. Developers who know stuff but forget/ignore them.

Our detailed explanations should help the first type while we hope our checklist helps the second one create more secure systems. This is by no means a comprehensive guide, it just covers stuff based on the most common issues we have discovered in the past.


### Contents

1. [The Security Checklist](security-checklist.md)
1. [Ecommerce Security CheckList](https://github.com/IamHDT/Ecommerce-Website-Security-CheckList)
3. [What can go wrong?](what-can-go-wrong.md)    
4. [Securely transporting stuff: HTTPS explained](https.md)
5. Authentication: I am who I say I am  
5.1 Form based authentication  
5.2 Basic authentication  
5.3 One is not enough, 2 factor, 3 factor, ....   
5.4 Why use insecure text messages? Introducing HOTP & TOTP   
5.5 Handling password resets
6. Authorization: What am I allowed to do?  
6.1 Token based Authorization  
6.2 OAuth & OAuth2  
6.3 JWT
7. Data Validation and Sanitation: Never trust user input  
7.1 Validating and Sanitizing Inputs  
7.2 Sanitizing Outputs  
7.3 Cross Site Scripting  
7.4 Injection Attacks  
7.5 User uploads  
7.6 Tamper-proof user inputs
8. Plaintext != Encoding != Encryption != Hashing  
8.1 Common encoding schemes  
8.2 Encryption  
7.3 Hashing & One way functions  
8.4 Hashing speeds cheatsheet
9. Passwords: dadada, 123456 and cute@123  
9.1 Password policies  
9.2 Storing passwords  
9.3 Life without passwords
10. Public Key Cryptography
11. Sessions: Remember me, please  
11.1 Where to save state?  
11.2 Invalidating sessions  
11.3 Cookie monster & you
12. Fixing security, one header at a time  
12.1 Secure web headers  
12.2 Data integrity check for 3rd party code  
12.3 Certificate Pinning
13. Configuration mistakes    
13.1 Provisioning in cloud: Ports, Shodan & AWS  
13.2 Honey, you left the debug mode on  
13.3 Logging (or not logging)  
13.4 Monitoring  
13.5 Principle of least privilege  
13.6 Rate limiting & Captchas  
13.7 Storing project secrets and passwords in a file    
13.8 DNS: Of subdomains and forgotten pet-projects  
13.9 Patching & Updates  
14. Attacks: When the bad guys arrive  
14.1 Clickjacking  
14.2 Cross Site Request Forgery  
14.3 Denial of Service  
14.4 Server Side Request Forgery
15. [Stats about vulnerabilities discovered in Internet Companies](vulnerabilities-stats.md)   
16. On reinventing the wheel, and making it square  
16.1 Security libraries and packages for Python  
16.2 Security libraries and packages for Node/JS  
16.3 Learning resources
17. Maintaining a good security hygiene
18. Security Vs Usability
19. Back to Square 1: The Security Checklist explained




### Who are we?

We are full stack developers who just grew tired of watching how developers were lowering the barrier to call something a hack by writing unsecure code. In the past six months, we have prevented leaks of more than 15 million credit card details, personal details of over 45 million users and potentially saved companies from shutting down. Recently, we discovered an issue that could result in system takeover and data leak in a bitcoin institution. We have helped several startups secure their systems, most of them for free, sometimes without even getting a thank you in response :)


*If you disagree with something or find a bug please open an issue or file a PR. Alternatively, you can talk to us on hello@fallible.co*
