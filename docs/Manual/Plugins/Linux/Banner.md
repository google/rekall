---
abstract: Prints the Linux banner information.
args: {}
class_name: Banner
epydoc: rekall.plugins.linux.cpuinfo.Banner-class.html
layout: plugin
module: rekall.plugins.linux.cpuinfo
title: banner
---

`banner` output provides the same information as running `uname -a` on the host.

### Sample output

```
Windows7_VMware(Win7x64+Ubuntu686,Ubuntu64)_VBox(XPSP3x86).ram 12:17:38> banner
-----------------------------------------------------------------------> banner()
Banner
--------------------------------------------------------------------------------
Linux version 3.11.0-12-generic (buildd@allspice) (gcc version 4.8.1 (Ubuntu/Linaro 4.8.1-10ubuntu7) ) #19-Ubuntu SMP Wed Oct 9 16:20:46 UTC 2013 (Ubuntu 3.11.0-12.19-generic 3.11.3)
```
