[Back to Contents](README.md)


### Hackerone publicly disclosed bugs Stats

Updated analysis of HackerOne vulnerability reports shows 12,618 total issues analyzed from the dataset.
All 12,618 issues were successfully classified using automated parsing and categorization.

    
    

#### Issues by type of mistake


| Classification | Count | Percentage |
| --- | --- |  --- |
| User Input Sanitization        | 4267     | 33.8
| Unclassified+Info+Junk         | 4066     | 32.2
| Other code issues              | 3350     | 26.5
| Configuration issues           | 935      | 7.4


#### Issues sorted by their frequency of occurrence

1 out of 3 issues were related to XSS, Information disclosure, or other code issues. The [Hackerone page](https://hackerone.com/hacktivity/new) listing these issues is quite interesting and can be read.

Type|Count|Percentage
| --- | --- | --- |
Other code issues|2599|20.60
XSS|2168|17.18
Information/Source Code Disclosure|1521|12.05
Unclassified+Info+Junk|1467|11.63
Broken/Open Authentication|868|6.88
SQL Injection|597|4.73
CSRF Token|468|3.71
Denial Of Service|458|3.63
Privilege Escalation|389|3.08
NULL POINTER + SEGFAULT + Using memory after free()|307|2.43
HTML/JS/XXE/Content Injections|299|2.37
Open Redirects|292|2.31
Insecure reference + Data Leak|263|2.08
Server Side Request Forgery|236|1.87
Path traversal|207|1.64
Buffer overflow|163|1.29
Clickjacking|129|1.02
Password Policy|67|0.53
Remote Code Execution|58|0.46
Improper Session management/Fixation|48|0.38
Integer overflow|13|0.10
Brute Force attacks|1|0.01


### Some unique vulnerability types

1. Race conditions based vulnerabilities
2. Pixel Flood Attack
3. IDN Homograph Attack
4. Control Characters in Input leading to interesting outcomes
