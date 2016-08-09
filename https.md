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

### How to get HTTPS as the owner of a website
### Precautions for general public
### Future of HTTPS
