---
abstract: Hexdump an object or memory location.
args: {address_space: The address space to use., data: Dump this string instead.,
  length: 'Maximum length to dump. (type: IntParser)

    ', offset: 'An offset to hexdump. (type: SymbolAddress)

    ', suppress_headers: 'Should headers be suppressed?. (type: Boolean)



    * Default: False'}
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
