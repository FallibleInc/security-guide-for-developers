### Securely transporting stuff: HTTPS explained


### The problem
The problem with HTTP without any S is that it sends and receives data in plain text. 

`Well, who can see my data in plain text?`

Well, anyone in your local network, your co-workers for example or people sitting around in your favourite cåfe. 

`How will they do it?`

They can tell the [switch](https://en.wikipedia.org/wiki/Network_switch) to deliver packets to their machine instead of yours by [ARP poisioning](https://en.wikipedia.org/wiki/ARP_spoofing) the ARP table maintained by the `switch` :
![ARP poisioning](/img/arp.png)

The owner of the cafe or your boss in your office can see your data by programming the hub/switch easily since they own and have physical access to it or [wire tapping](https://en.wikipedia.org/wiki/Fiber_tapping) the wire itself coming in to the cafe.

**Bad HTTP!**


### Enters HTTPS

![https](/img/https.gif) 

The 'S' in HTTPS stands for Secure i.e. if you are visiting any website on the internet that has the protocol `https` in the URI, then it is most likely secure. No one in the `middle` can sniff your traffic.

### How does it work?
HTTPS encrypts all the data that gets transferred between the browser and the server. The server and the browser uses a symmetric key known to both of them to encrypt the data. The process by which they arrive at the common key is called [TLS handshake](https://en.wikipedia.org/wiki/Transport_Layer_Security#TLS_handshake). In simple terms, the server sends its `public key` along with `domain name` embedded in a `certificate` to the browser, the browser sends back a `pre-master secret key` encyrpted using the server's public key. The server decrypts the encrypted message using its private key to obtain the pre-master secret key. Both the browser and the server now converts the pre-master key into the `master secret key` which is eventually used for encryption of all the future communications between server and the browser.

![Encryption](/img/encryption.png)

There is still one problem with the above process, that is, any [man in the middle](https://en.wikipedia.org/wiki/Man-in-the-middle_attack) can also generate a certificate and pretend to be the origin server and send malicious content to the browser. 

To solve that problem browser like Chrome, Firefox, Safari etc. come embedded with information to find out which certificates are genuine. Browsers look for signature in the certificate, the signature on the certificate needs to be from one of the certified certificate authorities. If there is no such signature in the certificate then the browser will display a warning to the user that this connection is not really HTTPS. The server on the other hand need to get the signed certificate from one of the certificate authority by physically verifying their identity(by sending docs etc.).

### How to get HTTPS for my website?

#### Best practices for https configuration, examples is for [nginx](https://www.nginx.com/) but settings for apache are available too ([mod_ssl](https://httpd.apache.org/docs/current/mod/mod_ssl.html) & [mod_headers](http://httpd.apache.org/docs/current/mod/mod_headers.html))
- [ ] update [openssl](https://www.openssl.org/source/) to the latest version available
- [ ] server-side protection from [BEAST attacks](https://en.wikipedia.org/wiki/Transport_Layer_Security#BEAST_attack)
       ```
       ssl_prefer_server_ciphers on;`

       ssl_ciphers "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:ECDHE-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA:DES-CBC3-SHA:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!MD5:!PSK:!RC4"; #Disables all weak ciphers
       ```

- [ ] support only TLSv1.1 and TLSv1.2. Do not support sslv2 and sslv3
       `ssl_protocols TLSv1.1 TLSv1.2;`

- [ ] do not use the default Diffie-Hellman parameter, locally generate param for more security
	```shell
	cd /etc/ssl/certs
	openssl dhparam -out dhparam.pem 4096
	```
       
       ```
       ssl_dhparam /etc/nginx/ssl/dhparam.pem;
	```
       
- [ ] don't send the nginx version number in error pages and Server header
       ```
	server_tokens off;
	```

- [ ] avoid clickjacking
       ```
	add_header X-Frame-Options SAMEORIGIN;
	```

- [ ] don't allow content type sniffing/guessing, combined with xss, this can be harmful
       ```
	add_header X-Content-Type-Options nosniff;
	```


- [ ] This header enables the Cross-site scripting (XSS) filter built into most recent web browsers. It's usually enabled by default anyway, so the role of this header is to re-enable the filter in case someone disabled it.
       ```
	add_header X-XSS-Protection "1; mode=block";
	```

- [ ]  with Content Security Policy (CSP) enabled you can tell the browser that it can only download content from the domains you explicitly allow, sample:
       ```
       add_header Content-Security-Policy "default-src 'self'; script-src 'self' https://code.jquery.com https://overseer.fallible.co https://www.google-analytics.com 'unsafe-inline'; style-src 'self' https://fonts.googleapis.com  https://overseer.fallible.co 'unsafe-inline'; font-src 'self' https://fallible.co https://code.ionicframework.com https://fonts.gstatic.com; img-src https://www.google-analytics.com https://overseer.fallible.co";
       ```
       
- [ ] config to enable HSTS(HTTP Strict Transport Security) to avoid [ssl stripping](https://en.wikipedia.org/wiki/SSL_stripping#SSL_stripping). This should not be a problem if ALL, yes, if ALL traffic is redirected to https
       ```add_header Strict-Transport-Security "max-age=31536000; includeSubdomains;";```

### Precautions for general public
### Future of HTTPS
