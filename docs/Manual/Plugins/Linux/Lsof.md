
---
layout: plugin
title: lsof
abstract: |
    Lists open files.

epydoc: rekall.plugins.linux.lsof.Lsof-class.html
---

Rekall walks the process table and dereferences each of the `task.files.fds` for each
kernel task.

### Sample output

```
$ python rekall/rekal.py -f ~/memory_images/Windows7_VMware\(Win7x64+Ubuntu686,Ubuntu64\)_VBox\(XPSP3x86\).ram  --ept 0x00017725001e - lsof 
[...]
libvirtd             1199            0       13 -                       0 -        -   
libvirtd             1199            0       14            0            0        0 socket:/NETLINK[0]
libvirtd             1199            0       15            0            0    12987 socket:/UNIX[12987]
libvirtd             1199            0       16 -                       0 -        proc
libvirtd             1199            0       17            0            0        0 socket:/NETLINK[0]
libvirtd             1199            0       18            0            0     8902 /run/libvirt/network/nwfilter.leases
libvirtd             1199            0       19            0            0     7861 -   
bash                 1335            0        0 -                       0 -        -   
bash                 1335            0        1 -                       0 -        -   
bash                 1335            0        2 -                       0 -        -   
bash                 1335            0      255 -                       0 -        -   
```
