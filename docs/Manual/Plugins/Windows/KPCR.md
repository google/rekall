---
abstract: A plugin to print all KPCR blocks.
args: {verbosity: 'An integer reflecting the amount of desired output: 0 = quiet,
    10 = noisy. (type: IntParser)



    * Default: 1'}
class_name: KPCR
epydoc: rekall.plugins.windows.kpcr.KPCR-class.html
layout: plugin
module: rekall.plugins.windows.kpcr
title: kpcr
---

Windows maintains per-processor information for each physical CPU in the
system. This plugin displays this infomation.

### Sample output

```
win8.1.raw 21:15:09> kpcr
-------------------> kpcr()
**************************************************
Property                       Value
------------------------------ -----
Offset (V)                     0xf802d3307000
KdVersionBlock                 Pointer to -
IDT                            0xf802d4a43080
GDT                            0xf802d4a43000
CurrentThread                 : 0xe00001254440 TID 3420 (winpmem_1.5.2.:2628)
IdleThread                    : 0xf802d335fa80 TID 0 (System:0)
Details                       : CPU 0 (GenuineIntel @ 2517 MHz)
CR3/DTB                       : 0x1a7000
```