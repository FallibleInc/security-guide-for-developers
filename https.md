# Securely transporting stuff: HTTPS explained


## The problem
HTTP is the protocol that the browsers use to communicate with the server. The problem with HTTP without any S is that it sends and receives data in plain text. 

#### Well, who can see my data in plain text?

Well, anyone in your local network, your co-workers for example or people sitting around you in your favourite cafe. 

#### How will they do it?

Since the data is in plain text, they can just tell the [switch](https://en.wikipedia.org/wiki/Network_switch) to deliver packets to their machine instead of yours by [ARP poisioning](https://en.wikipedia.org/wiki/ARP_spoofing) the ARP table maintained by the `switch` :
![ARP poisioning](/images/arp.png)

Also, the owner of the cafe or your boss in your office can see your data by programming the hub/switch easily since they own and have physical access to it or [wire tapping](https://en.wikipedia.org/wiki/Fiber_tapping) the wire itself coming in to the cafe.

**Bad HTTP!**


## Enters HTTPS

![https](/images/https.gif) 

The 'S' in HTTPS stands for Secure i.e. if you are visiting any website on the internet that has the protocol `https` in the URI, then it is most likely secure. No one in the `middle` can sniff your traffic.

### How does it work?
HTTPS encrypts all the data that gets transferred between the browser and the server. The server and the browser uses a symmetric key known to both of them to encrypt the data. The process by which they arrive at the common key is called [TLS handshake](https://en.wikipedia.org/wiki/Transport_Layer_Security#TLS_handshake). In simple terms, the server sends its `public key` along with `domain name` embedded in a `certificate` to the browser, the browser sends back a `pre-master secret key` encyrpted using the server's public key. The server decrypts the encrypted message using its private key to obtain the pre-master secret key. Both the browser and the server now converts the pre-master key into the `master secret key` which is eventually used for encryption of all the future communications between server and the browser.

![Encryption](/images/encryption.png)

There is still one problem with the above process, that is, any [man in the middle](https://en.wikipedia.org/wiki/Man-in-the-middle_attack) can also generate a certificate and pretend to be the origin server and send malicious content to the browser. 

To solve that problem browser like Chrome, Firefox, Safari etc. come embedded with information to find out which certificates are genuine. Browsers look for signature in the certificate, the signature on the certificate needs to be from one of the trusted [certificate authorities](https://en.wikipedia.org/wiki/Certificate_authority). In simple terms, certificate authorities are certain well-known organisations which everyone knows to be trust worthy (it all boils down to trust). If there is no such signature in the certificate then the browser will display a warning to the user that this connection is not really HTTPS. The server on the other hand need to get the signed certificate from one of the certificate authority by physically verifying their identity(by sending docs etc.).

So, `https` servers two main purpose 

	* It tells you that the website domain shown in the browser is the one you are actually talking to.
	* It encrypts all the communication between the domain in the browser and the browser itself.
	
### How to get HTTPS for my website?
#### There are two ways to get HTTPS to your website
1. Paid 
	* You need to buy a SSL certificate from some CAs 
	* Then you need to generate a certificate signing request from your server
	* Then they ask you to verify that you really own the domain.
	* Then they let you download the signed certificate which you can use in your server's configuration.
2. Free: 
	* Use [LetsEncrypt](https://letsencrypt.org/). Letsencrypt is free because the whole process is totally automated hence getting rid of the manual cost of configuration, creation, validation, expiration etc. 
	* To setup, follow the steps mentioned here depending on your server: [Setup steps](https://certbot.eff.org/#ubuntuxenial-nginx)
	

#### Best practices for https configuration, examples are for [nginx](https://www.nginx.com/) but settings for apache and others are available too ([ssl config generator](https://mozilla.github.io/server-side-tls/ssl-config-generator/))
- [ ] regularly update/patch [openssl](https://www.openssl.org/source/) to the latest version available because that will protect you from bugs like [heartbleed](https://en.wikipedia.org/wiki/Heartbleed) and [many more](https://www.openssl.org/news/secadv/20160503.txt).
- [ ] add this flag in nginx server conf for server-side protection from [BEAST attacks](https://en.wikipedia.org/wiki/Transport_Layer_Security#BEAST_attack)
       ```
	ssl_prefer_server_ciphers on;`

	ssl_ciphers "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:ECDHE-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA:DES-CBC3-SHA:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!MD5:!PSK:!RC4"; #Disables all weak ciphers
       ```

- [ ] Older versions of ssl protocols have been found to have multiple severe vulnerabilities (ex: [POODLE attack](https://en.wikipedia.org/wiki/POODLE), [DROWN attack](https://en.wikipedia.org/wiki/DROWN_attack)), so support only TLSv1.1 and TLSv1.2. Do not support sslv2 and sslv3. Do [check the adoption](https://en.wikipedia.org/wiki/Transport_Layer_Security#Web_browsers) to know the trade off of restricting to these versions of TLS.
       ```
	ssl_protocols TLSv1.1 TLSv1.2;
	```

- [ ] Default Diffie-Hellman parameter used by nginx is only 1024 bits which is considered not so secure. Also, it is same for all nginx users who use the default config. It is estimated that an academic team can break 768-bit primes and that a nation-state could break a 1024-bit prime. By breaking one 1024-bit prime, one could eavesdrop on 18 percent of the top one million HTTPS domains, so do not use the default DH parameter, locally generate the parameter for more security, also use higher number of bits.
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
In general any user who has an access to the app can see all the API calls even if it HTTPS. To do that he creates a certificate authority and tells the device (Android / iOS) to trust it. Now when you connect to the server it sits in between the server and the app and replaces your server's certificate with the one generated `on the fly` with its certificate (having own public/private `key` pair) signed by his own certificate authority and now he can sit in the middle and act as server for the mobile client and act as client for the server. Sneaky.

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

## Precautions for general public
* When you visit a website in your browser, make sure it displays the padlock like this ![padlock](/img/padlock.png) (will be gray in safari)
* If you are using an untrusted or public internet(wifi/wired) and you see striked out padlock and a warning page, then do not proceed, someone might be snooping on your traffic.
* iOS and Android apps have no way to tell if they are encrypting the traffic. Bad luck.
* Do not hand over your unloked mobile phones to any untrusted person. He/she might install certain untrusted `CAs` (certificate authorities) and can see all your traffic.
* If you use a mobile phone or laptop provided by the company then they might have installed certain `CAs` (certificates authorities) to be trusted by the device and can easily snoop on all your browsing. You should check if any `CA` is installed in your phone. Steps to check: In iOS, go to `Settings` -> `General` -> `Profiles`. If there is anything installed there then someone might be sniffing your traffic. In Android, go to `Settings`, under "Personal," tap `Security`, under "Credential storage," tap `Trusted credentials`. Check the certificates installed by user and system.


## Future of HTTPS
Web was built on HTTP protocol which lacks the security bit. Slowly people started to feel the need to have the channel secured, so that led to the birth of HTTPS. Still as of today majority of the websites are HTTP since thats the `default protocol`. If one needs to get HTTPS they use one of the methods mentioned in the section above "how to get https for my website". 

It would be awesome if all the websites use `https` instead of `http`. Also, all the browsers should force https, meaning they should fail the request if it is not `https`. Currently this is implemented using `HSTS` preload list but that is optional for websites to opt in but it would be nice if all the websites were forced to be https. This would improve the security of end users. There are lot of people promoting the move to https everywhere. 

But there is a problem with upgrading to https, that is, if some website was previously linked as http and now only works with https then that `http link` will break (as the links to this site would not get updated by the linker website). There are plugins to use [HTTPS everywhere](https://www.eff.org/Https-everywhere) which forces all the communication to be on `https://` if possible. But a better [proposal](https://www.w3.org/DesignIssues/Security-NotTheS.html) is to do HTTPS everywhere in the sense of the protocol but not the URI prefix - in that we do not need two different prefixes `http` and `https`, just make http use TLS fundamentally.
