---
abstract: Gathers active interfaces.
args: {verbosity: 'An integer reflecting the amount of desired output: 0 = quiet,
    10 = noisy. (type: IntParser)



    * Default: 1'}
class_name: Ifconfig
epydoc: rekall.plugins.linux.ifconfig.Ifconfig-class.html
layout: plugin
module: rekall.plugins.linux.ifconfig
title: ifconfig
---


### Sample output

```
[1] Windows7_VMware(Win7x64+Ubuntu686,Ubuntu64)_VBox(XPSP3x86).ram 16:12:17> ifconfig
---------------------------------------------------------------------------> ifconfig()
   Interface         Ipv4Address             MAC                Flags        
---------------- -------------------- ------------------ --------------------
lo               127.0.0.1            00:00:00:00:00:00  IFF_LOOPBACK, IFF_UP
eth0             192.168.239.129      00:0C:29:57:F7:19  IFF_BROADCAST, IFF_MULTICAST, IFF_UP
```
