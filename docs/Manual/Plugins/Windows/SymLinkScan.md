---
abstract: 'Scan for symbolic link objects '
args: {scan_in_kernel: 'Scan in the kernel address space (type: Boolean)



    * Default: False'}
class_name: SymLinkScan
epydoc: rekall.plugins.windows.filescan.SymLinkScan-class.html
layout: plugin
module: rekall.plugins.windows.filescan
title: symlinkscan
---

A symbolic link is a kernel object which maps a device from one name in the
kernel object tree to another name. Often a driver will set up a symbolic link
to a "dos device name" to allow access to a kernel device from userspace.

For example, the pmem driver makes a symbolic link from **\GLOBAL??\pmem** to
**\Devices\pmem** so that a user space program can use the **CreateFile** API to
open a handle to **\\.\pmem**.

This plugin scans for **_OBJECT_SYMBOLIC_LINK** objects using pool scanning techniques.

### Notes

1. Like other pool scanning plugins, this plugin may produce false positives
   since it essentially carves **_OBJECT_SYMBOLIC_LINK** structures out of
   memory. On the other hand, this plugin may reveal symlinks which have been
   closed or freed.

1. The interesting thing about a symlink is that it contains the timestamp of
   when it was created. This can be significant when determining when the system
   was compromised.

2. Since the *symlinkscan* plugin carves out **_OBJECT_SYMBOLIC_LINK** objects
   it has no context of where in the object tree the symlink exists. Hence it is
   unable to show parent object directories. A better plugin to use is the
   [object_tree](ObjectTree.html) plugin.

### Sample output

Here we see the **symlinkscan** plugin detecting the pmem link.

```
    Offset(P)      #Ptr   #Hnd Creation time            From To
- -------------- ------ ------ ------------------------ ---- ------------------------------------------------------------
  0x00000010d470      3      2 2014-01-24 22:07:29+0000 HDAUDIO#FUNC_01&VEN_8384&DEV_7680&SUBSYS_83847680&REV_1034#4&136d1aa0&0&0001#{65e8773e-8f56-11d0-a3b9-00a0c9223196} \Device\0000001e

  0x00000040e940      1      0 2014-01-24 22:07:23+0000 Psched \Device\Psched
  0x0000004e9490      2      1 2014-01-24 22:07:32+0000 DISPLAY#Default_Monitor#4&d9dcf0b&0&UID0#{e6f07b5f-ee97-4a90-b076-33f57bf4eaa7} \Device\00000021
...
  0x00002be706f0      2      1 2014-01-24 22:07:32+0000 AppContainerNamedObjects \Sessions\1\AppContainerNamedObjects
  0x00002bf89f20      2      1 2014-01-24 22:07:32+0000 Global \BaseNamedObjects
  0x00002c0b8270      2      1 2014-01-24 22:07:32+0000 1 \Sessions\1\BaseNamedObjects
  0x00002dbdbe00      1      0 2014-01-24 21:20:05+0000 pmem \Device\pmem
  0x00002f2b7240      1      0 2014-01-24 22:07:26+0000 HCD0 \Device\USBFDO-0
```