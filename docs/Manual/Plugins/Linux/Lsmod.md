
---
layout: plugin
title: lsmod
abstract: |
    Gathers loaded kernel modules.

epydoc: rekall.plugins.linux.lsmod.Lsmod-class.html
---

Rekall walks the list at kernel symbol `modules` to provide the list of modules.

### Sample output

```
[1] Windows7_VMware(Win7x64+Ubuntu686,Ubuntu64)_VBox(XPSP3x86).ram 16:22:54> lsmod
---------------------------------------------------------------------------> lsmod()

******************** Overview ********************
   Virtual       Core Start   Total Size         Name
-------------- -------------- ---------- --------------------
0xffffa038d120 0xffffa038b000      12880 ipt_MASQUERADE
0xffffa0383180 0xffffa0381000      13011 iptable_nat
```
