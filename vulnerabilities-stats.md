[Back to Contents](README.md)


### HackerOne publicly disclosed bugs Stats

At the time of writing, the HackerOne platform had 1731 publicly disclosed bugs in companies such as Twitter, Uber, Dropbox, Github etc.
8 of the bugs were removed as outright spam. 9 others were related to bugs in the Internet or a specific programming language. Out of the remaining 1714, we were able to classify 1359 issues using some code and manual work.

    
    

#### Issues by type of mistake


| Classification | Count | Percentage |
| --- | --- |  --- |
| User Input Sanitization        | 481      | 27.8
| Other code issues              | 549      | 31.7
| Configuration issues           | 325      | 18.8
| Unclassified+Info+Junk         | 376      | 21.7


#### Issues sorted by their frequency of occurence 

1 out of 3 issues were related to XSS, Insecure references to data (data leak) or missing CSRF token. The [HackerOne page](https://hackerone.com/hacktivity/new) listing these issues is quite interesting and can be read.

Type|Count|Percentage
| --- | --- | --- |
XSS|375|21.87
Insecure reference + Data Leak|104|6.06
CSRF Token|99|5.77
Open Redirects|59|3.44
Information/Source Code Disclosure|57|3.32
DNS misconfiguration + Apache/Nginx + Subdomain Takeover + Open AWS_S3|44|2.56
Improper Session management/Fixation|39|2.27
TLS/SSL/POODLE/Heartbleed|39|2.27
HTML/JS/XXE/Content Injections|37|2.15
HTTP Header Issues|34|1.98
NULL POINTER + SEGFAULT + Using memory after free()|33|1.92
DMARC/DKIM/SPF settings for Mail|31|1.8
SQL Injection|28|1.63
Clickjacking|27|1.57
Improper Cookies (secure/httpOnly/exposed)|25|1.45
Path disclosure|25|1.45
Broken/Open Authentication|24|1.4
Brute Force attacks|24|1.4
Content Spoofing|20|1.16
Buffer overflow|20|1.16
Denial Of Service|19|1.1
Server Side Request Forgery|18|1.05
Adobe Flash vulnerabilities|18|1.05
User/Info Enumeration|17|0.99
Remote Code Execution|15|0.87
Password reset token expiration/attempts/others|13|0.75
Integer overflow|11|0.64
Version Disclosure|11|0.64
CSV Injection|10|0.58
Privilege Escalation|9|0.52
OAuth state/leaks and other issues|9|0.52
Password Policy|7|0.4
CRLF|7|0.4
PythonLang|6|0.35
Homograph attack|6|0.35
File upload type/size/location sanitize|6|0.35
Captcha bypass|5|0.29
Remote/Local File inclusion|4|0.23
Directory listing|4|0.23
Path traversal|4|0.23
Remote File Upload|4|0.23
Autocomplete enabled|4|0.23
Leak through referer|3|0.17
Pixel Flood Attack|3|0.17
Control Chars in Input|2|0.11


### Some unique vulnerability types

1. Race conditions based vulnerabilities
2. Pixel Flood Attack
3. IDN Homograph Attack
4. Control Characters in Input leading to interesting outcomes
