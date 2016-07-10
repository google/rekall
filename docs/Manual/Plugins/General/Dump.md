---
abstract: "Hexdump an object or memory location.\n\n    You can use this plugin repeateadely\
  \ to keep dumping more data using the\n     \"p _\" (print last result) operation:\n\
  \n    In [2]: dump 0x814b13b0, address_space=\"K\"\n    ------> dump(0x814b13b0,\
  \ address_space=\"K\")\n    Offset                         Hex                 \
  \             Data\n    ---------- ------------------------------------------------\
  \ ----------------\n    0x814b13b0 03 00 1b 00 00 00 00 00 b8 13 4b 81 b8 13 4b\
  \ 81  ..........K...K.\n\n    Out[3]: <rekall.plugins.core.Dump at 0x2967510>\n\n\
  \    In [4]: p _\n    ------> p(_)\n    Offset                         Hex     \
  \                         Data\n    ---------- ------------------------------------------------\
  \ ----------------\n    0x814b1440 70 39 00 00 54 1b 01 00 18 0a 00 00 32 59 00\
  \ 00  p9..T.......2Y..\n    0x814b1450 6c 3c 01 00 81 0a 00 00 18 0a 00 00 00 b0\
  \ 0f 06  l<..............\n    0x814b1460 00 10 3f 05 64 77 ed 81 d4 80 21 82 00\
  \ 00 00 00  ..?.dw....!.....\n    "
args: {address_space: 'The address space to use. (type: AddressSpace)

    ', data: 'Dump this string instead. (type: String)

    ', length: 'Maximum length to dump. (type: IntParser)

    ', offset: 'An offset to hexdump. (type: SymbolAddress)



    * Default: 0', rows: 'Number of bytes per row (type: IntParser)

    ', width: 'Number of bytes per row (type: IntParser)

    '}
class_name: Dump
epydoc: rekall.plugins.core.Dump-class.html
layout: plugin
module: rekall.plugins.core
title: dump
---

If you need to produce a hexdump of a region of memory, use the `dump`
plugin. This plugin accepts a single symbol name or address in the default
address space (see the `cc` plugin).

The `dump` plugin will also show which symbol address is known to exist in every
offset displayed. This is done via the Rekall address resolver. If colors are
enabled, known symbols are highlighted in different colors both in the comment
field and inside the hexdump area itself.

In the below example we dump the 'SeTcbPrivilege' symbol from the nt
kernel. Also shown are other symbols located in the vicinity.

```text
[1] win7.elf 22:32:36> dump "nt!SeTcbPrivilege"
---------------------> dump("nt!SeTcbPrivilege")
Offset                                   Data                                                Comment
-------------- ----------------------------------------------------------------- ----------------------------------------
0xf80002b590b8 07 00 00 00 00 00 00 00 44 02 01 00 80 f9 ff ff  ........D....... nt!SeTcbPrivilege, nt!NlsOemToUnicodeData
0xf80002b590c8 00 00 00 00 00 01 00 00 00 00 00 00 00 00 00 00  ................ nt!VfRandomVerifiedDrivers, nt!TunnelMaxEntries, nt!ExpBootLicensingData
0xf80002b590d8 bc 00 00 00 00 10 00 00 00 00 ff 07 80 f8 ff ff  ................ nt!ExpLicensingDescriptorsCount, nt!CmpStashBufferSize, nt!ExpLicensingView
0xf80002b590e8 e8 f5 00 00 a0 f8 ff ff e8 45 7a 05 a0 f8 ff ff  .........Ez..... nt!CmpHiveListHead
0xf80002b590f8 1c 00 00 00 80 f9 ff ff 16 00 00 00 00 00 00 00  ................ nt!NlsAnsiToUnicodeData, nt!SeSystemEnvironmentPrivilege
```
