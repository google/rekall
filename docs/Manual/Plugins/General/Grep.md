---
abstract: Search an address space for keywords.
args: {address_space: 'Name of the address_space to search. (type: AddressSpace)

    ', context: 'Context to print around the hit. (type: IntParser)



    * Default: 20', keyword: 'The binary strings to find. (type: ArrayString)

    ', limit: 'The length of data to search. (type: String)



    * Default: 18446744073709551616', offset: 'Start searching from this offset. (type:
    IntParser)



    * Default: 0'}
class_name: Grep
epydoc: rekall.plugins.core.Grep-class.html
layout: plugin
module: rekall.plugins.core
title: grep
---

Sometimes we want to search for some data in the address space. Although we can
use `yarascan` to do this, it is typically slower than just running the `grep`
plugin. Note that the plugin can scan the entire address space efficiently
(i.e. it will automatically skip over sparse memory regions).

One of the more interesting uses of the `grep` plugin is looking for
references. For example, suppose we wanted to see who has a reference to a
particular _EPROCESS structure.

In the below example, we pick an _EPROCESS from the output of `pslist` and
search for pointers to it somewhere in kernel memory (There are many pointers!
We just picked one for this example.). We then use the `analyze_struct` plugin
to discover that the pointer resides in an allocation with the pool tag
'ObHd'. We can search the kernel disassembly to realize this is an Object
Handle. Note how we use grep to search for the little endian representation of
the _EPROCESS address.

```text
[1] win7.elf 23:14:38> pslist
  _EPROCESS            Name          PID   PPID   Thds    Hnds    Sess  Wow64           Start                     Exit
-------------- -------------------- ----- ------ ------ -------- ------ ------ ------------------------ ------------------------
....
0xfa8002ad0190 cmd.exe               2644   2616      2       66      1 True   2012-10-01 14:40:20Z     -

[1] win7.elf 23:14:55> grep keyword="\x90\x01\xad\x02\x80\xfa"
....
    Offset                                   Data                                                Comment
-------------- ----------------------------------------------------------------- ----------------------------------------
0xf8a0013d8ad8 60 40 a9 02 80 fa ff ff 01 00 00 00 00 00 00 00  `@..............
0xf8a0013d8ae8 90 01 ad 02 80 fa ff ff 01 00 00 00 00 00 00 00  ................
0xf8a0013d8af8 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
...
[1] win7.elf 23:17:20> analyze_struct 0xf8a0013d8ae8

0xf8a0013d8ae8 is inside pool allocation with tag 'ObHd' (0xf8a0013d8a30)  and size 0x100
    Offset     Content
-------------- -------
           0x0 Data:0xfa8002ad0190 Tag:Pro\xe3 @0xfa8002ad0190 (0x530)
           0x8 Data:0x1
          0x10 Data:0x0
          0x18 Data:0x0
          0x20 Data:0x0
          0x28 Data:0x0
          0x30 Data:0xfa80017f9060 Tag:Pro\xe3 @0xfa80017f9060 (0x530)
          0x38 Data:0x1
          0x40 Data:0x730061006c
          0x48 Data:0x744e034d0110
          0x50 Data:0x490053004c
          0x58 Data:0xa4801280702
          0x60 Data:0x981e
          0x68 Data:0x100000000
          0x70 Data:0x0
[1] win7.elf 23:22:25> hex(struct.unpack("<I", 'ObHd')[0])
               Out<24> '0x6448624f'
[1] win7.elf 23:22:33> dis "nt!ObpInsertHandleCount"
---------------------> dis("nt!ObpInsertHandleCount")
Address      Rel             Op Codes                     Instruction                Comment
------- -------------- -------------------- ---------------------------------------- -------
------ nt!ObpInsertHandleCount ------: 0xf80002976010
  0xf80002976010            0x0 48895c2408           mov qword ptr [rsp + 8], rbx
  0xf80002976015            0x5 48896c2410           mov qword ptr [rsp + 0x10], rbp
....

  0xf80002976089           0x79 41b84f624864         mov r8d, 0x6448624f
  0xf8000297608f           0x7f e83cd3e4ff           call 0xf800027c33d0                      nt!ExAllocatePoolWithTag
  0xf80002976094           0x84 4885c0               test rax, rax
  0xf80002976097           0x87 0f84dacd0400         je 0xf800029c2e77                        nt!ExpProfileCreate+0x9d57
  0xf8000297609d           0x8d 458bc5               mov r8d, r13d
```
