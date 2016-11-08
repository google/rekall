---
abstract: print the ARP table.
args: {verbosity: 'An integer reflecting the amount of desired output: 0 = quiet,
    10 = noisy. (type: IntParser)



    * Default: 1'}
class_name: Arp
epydoc: rekall.plugins.linux.arp.Arp-class.html
layout: plugin
module: rekall.plugins.linux.arp
title: arp
---

`arp` returns the list of IPv4 network neighbour entries in the kernel cache.

Rekall uses the `neigh_tables` kernel symbol and walks the neighbour tables to
show the entries.

### Sample output

```
Windows7_VMware(Win7x64+Ubuntu686,Ubuntu64)_VBox(XPSP3x86).ram 12:09:00> arp
-----------------------------------------------------------------------> arp()
                                   IP Address                  MAC          Device
--------------------------------------------- -------------------- ---------------
                            ff02::1:ff57:f719    33:33:ff:57:f7:19            eth0
                                     ff02::16    33:33:00:00:00:16            eth0
                                192.168.239.2    00:50:56:e5:38:b6            eth0
                              192.168.239.254    00:50:56:f7:25:d0            eth0
```
