### Securely transporting stuff: HTTPS explained


### The problem
The problem with HTTP without any S is that it sends and receives data in plain text. 

`Well, who can see my data in plain text?`

Well, anyone in your local network, your co-workers for example or people sitting around in your favourite cåfe. 

`How will they do it?`

They can tell the `switch` to deliver packets to their machine instead of yours by [ARP poisioning](https://en.wikipedia.org/wiki/ARP_spoofing) the ARP table maintained by the `switch` :
![ARP poisioning](/img/arp.png)

The owner of the cafe or your boss in your office can see your data by programming the hub/switch easily since they own and have physical access to it or [wire tapping](https://en.wikipedia.org/wiki/Fiber_tapping) the wire itself coming in to the cafe.

**Bad HTTP!**


### Enters HTTPS

![https](/img/https.gif) 

The 'S' in HTTPS stands for Secure i.e. if you are visiting any website on the internet that has the protocol `https` in the URI, then it is most likely secure. No one in the `middle` can sniff your traffic.
