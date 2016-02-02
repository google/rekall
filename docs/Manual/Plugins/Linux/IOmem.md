---
abstract: mimics /proc/iomem.
args: {}
class_name: IOmem
epydoc: rekall.plugins.linux.iomem.IOmem-class.html
layout: plugin
module: rekall.plugins.linux.iomem
title: iomem
---

### Sample output

```
[1] Windows7_VMware(Win7x64+Ubuntu686,Ubuntu64)_VBox(XPSP3x86).ram 16:22:13> iomem
---------------------------------------------------------------------------> iomem()
   Resource         Start           End       Name
--------------  -------------- -------------- ----
0xffff81c3abc0  0x000000000000 0x00ffffffffff 
0x88003fff9b00 . 0x000000000000 0x000000000fff reserved
0x88003fff9b38 . 0x000000001000 0x00000009ebff System RAM
0x88003fff9b70 . 0x00000009ec00 0x00000009ffff reserved
0x88003d112200 . 0x0000000a0000 0x0000000bffff PCI Bus 0000:00
0xffff81c1aac0 . 0x0000000c0000 0x0000000c7fff Video ROM
0x88003fff9ba8 . 0x0000000ca000 0x0000000cbfff reserved
0xffff81c1ab00 .. 0x0000000ca000 0x0000000cafff Adapter ROM
0x88003d112238 . 0x0000000d0000 0x0000000d3fff PCI Bus 0000:00
0x88003d112270 . 0x0000000d4000 0x0000000d7fff PCI Bus 0000:00
0x88003d1122a8 . 0x0000000d8000 0x0000000dbfff PCI Bus 0000:00
0x88003fff9be0 . 0x0000000dc000 0x0000000fffff reserved
0xffff81c1aca0 .. 0x0000000f0000 0x0000000fffff System ROM
0x88003fff9c18 . 0x000000100000 0x00003fedffff System RAM
0xffff81c1a6a0 .. 0x000001000000 0x0000016f9945 Kernel code
0xffff81c1a6e0 .. 0x0000016f9946 0x000001d0e7ff Kernel data
0xffff81c1a660 .. 0x000001e6d000 0x000001fcffff Kernel bss
0x88003fff9c50 . 0x00003fee0000 0x00003fefefff ACPI Tables
0x88003fff9c88 . 0x00003feff000 0x00003fefffff ACPI Non-volatile Storage
0x88003fff9cc0 . 0x00003ff00000 0x00003fffffff System RAM
0x88003d1122e0 . 0x0000c0000000 0x0000febfffff PCI Bus 0000:00
0x88003d1a0488 .. 0x0000c0000000 0x0000c0007fff 0000:00:0f.0
0x88003d1a1488 .. 0x0000c0008000 0x0000c000bfff 0000:00:10.0
0x88003d202680 .. 0x0000e5b00000 0x0000e5bfffff 
0x88003d1da680 .. 0x0000e5c00000 0x0000e5cfffff PCI Bus 0000:1a
0x88003d1d2680 .. 0x0000e5d00000 0x0000e5dfffff PCI Bus 0000:12
0x88003d1ca680 .. 0x0000e5e00000 0x0000e5efffff 
0x88003d201680 .. 0x000000000000 0x000000000000 -   
0x88003fff9d30 . 0x0000fec00000 0x0000fec0ffff reserved
0x88003fff9e00 .. 0x0000fec00000 0x0000fec003ff IOAPIC 0
0x88003fff9e80 . 0x0000fed00000 0x0000fed003ff HPET 0
0x88003d2ca500 .. 0x0000fed00000 0x0000fed003ff pnp 00:07
0xffff81c25cc0 . 0x0000fee00000 0x0000fee00fff Local APIC
0x88003fff9d68 .. 0x0000fee00000 0x0000fee00fff reserved
0x88003fff9da0 . 0x0000fffe0000 0x0000ffffffff reserved
```
