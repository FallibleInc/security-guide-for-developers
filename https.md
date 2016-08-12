# Securely transporting stuff: HTTPS explained


## The problem
The problem with HTTP without any S is that it sends and receives data in plain text. 

#### Well, who can see my data in plain text?

Well, anyone in your local network, your co-workers for example or people sitting around in your favourite cåfe. 

#### How will they do it?

They can tell the [switch](https://en.wikipedia.org/wiki/Network_switch) to deliver packets to their machine instead of yours by [ARP poisioning](https://en.wikipedia.org/wiki/ARP_spoofing) the ARP table maintained by the `switch` :
![ARP poisioning](/img/arp.png)

The owner of the cafe or your boss in your office can see your data by programming the hub/switch easily since they own and have physical access to it or [wire tapping](https://en.wikipedia.org/wiki/Fiber_tapping) the wire itself coming in to the cafe.

**Bad HTTP!**


## Enters HTTPS

![https](/img/https.gif) 

The 'S' in HTTPS stands for Secure i.e. if you are visiting any website on the internet that has the protocol `https` in the URI, then it is most likely secure. No one in the `middle` can sniff your traffic.

### How does it work?
HTTPS encrypts all the data that gets transferred between the browser and the server. The server and the browser uses a symmetric key known to both of them to encrypt the data. The process by which they arrive at the common key is called [TLS handshake](https://en.wikipedia.org/wiki/Transport_Layer_Security#TLS_handshake). In simple terms, the server sends its `public key` along with `domain name` embedded in a `certificate` to the browser, the browser sends back a `pre-master secret key` encyrpted using the server's public key. The server decrypts the encrypted message using its private key to obtain the pre-master secret key. Both the browser and the server now converts the pre-master key into the `master secret key` which is eventually used for encryption of all the future communications between server and the browser.

![Encryption](/img/encryption.png)

There is still one problem with the above process, that is, any [man in the middle](https://en.wikipedia.org/wiki/Man-in-the-middle_attack) can also generate a certificate and pretend to be the origin server and send malicious content to the browser. 

To solve that problem browser like Chrome, Firefox, Safari etc. come embedded with information to find out which certificates are genuine. Browsers look for signature in the certificate, the signature on the certificate needs to be from one of the trusted [certificate authorities](https://en.wikipedia.org/wiki/Certificate_authority). If there is no such signature in the certificate then the browser will display a warning to the user that this connection is not really HTTPS. The server on the other hand need to get the signed certificate from one of the certificate authority by physically verifying their identity(by sending docs etc.).

### How to get HTTPS for my website?
#### There are two ways to get HTTPS to your website
1. Paid 
	* TODO
2. Free
	* TODO

#### Best practices for https configuration, examples are for [nginx](https://www.nginx.com/) but settings for apache are available too ([mod_ssl](https://httpd.apache.org/docs/current/mod/mod_ssl.html) & [mod_headers](http://httpd.apache.org/docs/current/mod/mod_headers.html))
- [ ] regularly update/patch [openssl](https://www.openssl.org/source/) to the latest version available because that will protect you from bugs like [heartbleed](https://en.wikipedia.org/wiki/Heartbleed) and [many more](https://www.openssl.org/news/secadv/20160503.txt).
- [ ] add this flag in nginx server conf for server-side protection from [BEAST attacks](https://en.wikipedia.org/wiki/Transport_Layer_Security#BEAST_attack)
       ```
	ssl_prefer_server_ciphers on;`

	ssl_ciphers "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:ECDHE-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA:DES-CBC3-SHA:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!MD5:!PSK:!RC4"; #Disables all weak ciphers
       ```

- [ ] Older versions of ssl protocols have been found to have multiple severe vulnerabilities, so support only TLSv1.1 and TLSv1.2. Do not support sslv2 and sslv3.
       ```
	ssl_protocols TLSv1.1 TLSv1.2;
	```

- [ ] Default Diffie-Hellman parameter used by nginx is only 1024 bits and is considered not so secure, so do not use the default DH parameter, locally generate the parameter for more security
	```shell
	$ cd /etc/ssl/certs
	$ openssl dhparam -out dhparam.pem 4096
	```
       
       ```
	ssl_dhparam /etc/nginx/ssl/dhparam.pem;
       ```
       
- [ ] config to enable HSTS(HTTP Strict Transport Security) to avoid [ssl stripping](https://en.wikipedia.org/wiki/SSL_stripping#SSL_stripping). This should not be a problem if ALL, yes, if ALL traffic is redirected to https
       ```
	add_header Strict-Transport-Security "max-age=31536000; includeSubdomains;";
       ```

## Certificate Pinning for apps (and website)
#### What's this now?
In general any user who has an access to the app can see all the API calls even if it HTTPS. To do that he creates a certificate authority and tells the device (Android / iOS) to trust it. Now when you connect to the server it replaces your server's certificate with the one generated `on the fly` with its certificate (own public/private `key` pair) and now he can sit in the middle and act as server for the mobile client and act as client for the server. Sneaky.

#### Wait! Isn't HTTPS supposed to prevent that?
Yes, but HTTPS can only help you when the trusted certificate authorities are actually trust worthy. In this case, the user forced the device to trust his own created certificate authority! 

#### So, how do I prevent that?
Certificate pinning - Basically, in your app bundle, hard code the server certificate and before doing any API call check whether the server is really using that same hardcoded certificate or someone tried to sneak in his own certificate.

#### Caution
* In case the certificate changes on the server side you will have to force the users to update the app else the app will stop working.
* If you mess up the certificate pinning, you will have to ask users to update the app else the app will stop working.

#### A better way!
Certificate pinning is a good way to prevent this but there is one better way to ensure no one can snoop in - use `public key pinning`. Generally sites like Google rotates its certificate so you will have to force users to update your app. Instead what you should pin in your app is the `public key` which remains static even when Google rotates its certificate hence not needing any app update. This is called `Public key Pinning`.

* Android and iOS sample code examples: 
```
https://www.paypal-engineering.com/2015/10/14/key-pinning-in-mobile-applications/
```

### Precautions for general public
#TODO

### Future of HTTPS
#TODO
