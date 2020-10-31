# A practical security guide for web developers (Work in progress)

### The intended audience

Security issues happen for two reasons - 

1. Developers who have just started and cannot really tell a difference between using MD5 or bcrypt.
2. Developers who know stuff but forget/ignore them.

Our detailed explanations should help the first type while we hope our checklist helps the second one create more secure systems. This is by no means a comprehensive guide, it just covers stuff based on the most common issues we have discovered in the past.


### Contents

1. [The Security Checklist](security-checklist.md)
2. [What can go wrong?](what-can-go-wrong.md)    
3. [Securely transporting stuff: HTTPS explained](https.md)
4. Authentication: I am who I say I am  
4.1 Form based authentication  
4.2 Basic authentication  
4.3 One is not enough, 2 factor, 3 factor, ....   
4.4 Why use insecure text messages? Introducing HOTP & TOTP   
4.5 Handling password resets
5. Authorization: What am I allowed to do?  
5.1 Token based Authorization  
5.2 OAuth & OAuth2  
5.3 JWT
6. Data Validation and Sanitation: Never trust user input  
6.1 Validating and Sanitizing Inputs  
6.2 Sanitizing Outputs  
6.3 Cross Site Scripting  
6.4 Injection Attacks  
6.5 User uploads  
6.6 Tamper-proof user inputs
7. Plaintext != Encoding != Encryption != Hashing  
7.1 Common encoding schemes  
7.2 Encryption  
7.3 Hashing & One way functions  
7.4 Hashing speeds cheatsheet
8. Passwords: dadada, 123456 and cute@123  
8.1 Password policies  
8.2 Storing passwords  
8.3 Life without passwords
9. Public Key Cryptography
10. Sessions: Remember me, please  
10.1 Where to save state?  
10.2 Invalidating sessions  
10.3 Cookie monster & you
11. Fixing security, one header at a time  
11.1 Secure web headers  
11.2 Data integrity check for 3rd party code  
11.3 Certificate Pinning
12. Configuration mistakes    
12.1 Provisioning in cloud: Ports, Shodan & AWS  
12.2 Honey, you left the debug mode on  
12.3 Logging (or not logging)  
12.4 Monitoring  
12.5 Principle of least privilege  
12.6 Rate limiting & Captchas  
12.7 Storing project secrets and passwords in a file    
12.8 DNS: Of subdomains and forgotten pet-projects  
12.9 Patching & Updates  
13. Attacks: When the bad guys arrive  
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




### Who are we?

We are full stack developers who just grew tired of watching how developers were lowering the barrier to call something a hack by writing unsecure code. In the past six months, we have prevented leaks of more than 15 million credit card details, personal details of over 45 million users and potentially saved companies from shutting down. Recently, we discovered an issue that could result in system takeover and data leak in a bitcoin institution. We have helped several startups secure their systems, most of them for free, sometimes without even getting a thank you in response :)


*If you disagree with something or find a bug please open an issue or file a PR. Alternatively, you can talk to us on hello@fallible.co*
