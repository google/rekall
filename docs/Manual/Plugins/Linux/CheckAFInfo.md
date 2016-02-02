---
abstract: Verifies the operation function pointers of network protocols.
args: {}
class_name: CheckAFInfo
epydoc: rekall.plugins.linux.check_afinfo.CheckAFInfo-class.html
layout: plugin
module: rekall.plugins.linux.check_afinfo
title: check_afinfo
---

The plugin identifies the location of each function pointer of different
network protocols. If located within the kernel or a loaded module, rekall
will give such information as well as its kernel-space address.

If malware dynamically allocates memory and copies code there to handle
these functions, the Module column will appear as Unknown.

### Sample output
```
Windows7_VMware(Win7x64+Ubuntu686,Ubuntu64)_VBox(XPSP3x86).ram 13:51:35> check_afinfo
-----------------------------------------------------------------------> check_afinfo()
Constant Name                  Member                            Address     Module
------------------------------ ------------------------------ -------------- --------------------
tcp4_seq_afinfo                seq_fops.llseek                0xffff811c9250 Kernel
tcp4_seq_afinfo                seq_fops.read                  0xffff811c9460 Kernel
tcp4_seq_afinfo                seq_fops.release               0xffff812157d0 Kernel
udplite6_seq_afinfo            seq_ops.show                   0xffff816a1300 Kernel
udplite6_seq_afinfo            seq_fops.llseek                0xffff811c9250 Kernel
udplite6_seq_afinfo            seq_fops.read                  0xffff811c9460 Kernel
udplite6_seq_afinfo            seq_fops.release               0xffff812157d0 Kernel
udp6_seq_afinfo                seq_ops.show                   0xffff816a1300 Kernel
udp6_seq_afinfo                seq_fops.llseek                0xffff811c9250 Kernel
udp6_seq_afinfo                seq_fops.read                  0xffff811c9460 Kernel
udp6_seq_afinfo                seq_fops.release               0xffff812157d0 Kernel
udplite4_seq_afinfo            seq_ops.show                   0xffff8164f9e0 Kernel
udplite4_seq_afinfo            seq_fops.llseek                0xffff811c9250 Kernel
udplite4_seq_afinfo            seq_fops.read                  0xffff811c9460 Kernel
udplite4_seq_afinfo            seq_fops.release               0xffff812157d0 Kernel
udp4_seq_afinfo                seq_ops.show                   0xffff8164f9e0 Kernel
udp4_seq_afinfo                seq_fops.llseek                0xffff811c9250 Kernel
udp4_seq_afinfo                seq_fops.read                  0xffff811c9460 Kernel
udp4_seq_afinfo                seq_fops.release               0xffff812157d0 Kernel
```
