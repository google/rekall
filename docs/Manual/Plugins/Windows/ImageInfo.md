---
layout: plugin
title: imageinfo
abstract: |
  List overview information about this image.

epydoc: rekall.plugins.windows.misc.ImageInfo-class.html
args:

---

This plugin prints an overview of certain parameters of the image.


### Notes

1. Since Rekall does not require users to select the profiles manually this
   plugin is not required to be run prior to any analysis. In fact the plugin
   itself needs to have accurate profiles loaded. It therefore does not server
   the same purpose as in previous version of the software.


### Sample output

```
win8.1.raw 18:00:48> imageinfo
-------------------> imageinfo()
Fact                 Value
-------------------- -----
Kernel DTB           0x1a7000
NT Build             9600.winblue_gdr.130913-2141
NT Build Ex          9600.16404.amd64fre.winblue_gdr.130913-2141
Signed Drivers       -
Time (UTC)           2014-01-24 21:20:05+0000
Time (Local)         2014-01-24 21:20:05+0000
Sec Since Boot       764.359375
NtSystemRoot         C:\Windows
**************** Physical Layout ****************
Physical Start  Physical End  Number of Pages
-------------- -------------- ---------------
0x000000001000 0x00000009f000 158
0x000000100000 0x000000102000 2
0x000000103000 0x00003fff0000 261869
```
