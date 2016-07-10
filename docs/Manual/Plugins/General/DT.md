---
abstract: "Print a struct or other symbol.\n\n    Really just a convenience function\
  \ for instantiating the object and printing\n    all its members.\n    "
args: {address_space: 'The address space to use. (type: AddressSpace)

    ', member_offset: 'If specified we only show the member at this offset. (type:
    IntParser)

    ', offset: 'Name of a struct definition. (type: IntParser)



    * Default: 0', target: 'Name of a struct definition. (type: String)

    '}
class_name: DT
epydoc: rekall.plugins.core.DT-class.html
layout: plugin
module: rekall.plugins.core
title: dt
---

The `dt` plugin prints all the fields within a data structure and optionally,
their contents.

In the example below, we create an `_EPROCESS` instance over a specific virtual
address (this was taken from the output of the `pslist` plugin). The `dt` plugin
displays all the fields in the struct. If there is a nested struct, the `dt`
plugin shows a tree view of the nested struct as well.

Note that if an address is not specified, the `_EPROCESS` object will simply be
instantiated over address 0 and all offsets will be relative to the begining of
the struct. This is very useful when deciphering assembly code which
dereferences members of the struct.

Rekall also uses "virtual members" on structs, mostly placed there for
convenience or to support multiple versions of the same struct. We can see in
this case that the fields "name" and "pid" are virtual members since their
offset is -1. These represent the name and the pid of the process in all
operating systems.

```text
[1] win7.elf 19:34:27> dt session.profile._EPROCESS(0xfa8002a94060)
---------------------> dt(session.profile._EPROCESS(0xfa8002a94060))
[_EPROCESS _EPROCESS] @ 0xfa8002a94060
Offset             Field              Content
------ ------------------------------ -------
            0x-1    RealVadRoot                    [_MMADDRESS_NODE BalancedRoot] @ 0xFA8002A944A8
. 0xfa8002a9449c    Tag                             [String:Tag]: '\x14\xd0\x02\x00'
. 0xfa8002a944a8    u1                             [<unnamed-5580> u1] @ 0xFA8002A944A8
.. 0xfa8002a944a8    Balance                         [BitField(0-2):Balance]: 0x00000000
.. 0xfa8002a944a8    Parent                         <_MMADDRESS_NODE Pointer to [0xFA8002A944A8] (Parent)>
. 0xfa8002a944b0    LeftChild                      <_MMADDRESS_NODE Pointer to [0x00000000] (LeftChild)>
. 0xfa8002a944b8    RightChild                     <_MMADDRESS_NODE Pointer to [0xFA8002A92710] (RightChild)>
. 0xfa8002a944c0    StartingVpn                     [unsigned long long:StartingVpn]: 0x00000000
. 0xfa8002a944c8    EndingVpn                       [unsigned long long:EndingVpn]: 0x00000000
            0x-1    dtb                            112128000
            0x-1    name                            [String:ImageFileName]: 'Console.exe\x00'
            0x-1    pid                             [unsigned int:UniqueProcessId]: 0x00000A38
  0xfa8002a94060    Pcb                            [_KPROCESS Pcb] @ 0xFA8002A94060
. 0xfa8002a94060    Header                         [_DISPATCHER_HEADER Header] @ 0xFA8002A94060
.. 0xfa8002a94060    Lock                            [long:Lock]: 0x00580003
.. 0xfa8002a94060    Type                            [Enumeration:Type]: 0x00000003 (ProcessObject)
.. 0xfa8002a94061    Abandoned                       [unsigned char:Abandoned]: 0x00000000
.. 0xfa8002a94061    Absolute                        [BitField(0-1):Absolute]: 0x00000000
.. 0xfa8002a94061    Coalescable                     [BitField(1-2):Coalescable]: 0x00000000
.. 0xfa8002a94061    EncodedTolerableDelay           [BitField(3-8):EncodedTolerableDelay]: 0x00000000
.. 0xfa8002a94061    KeepShifting                    [BitField(2-3):KeepShifting]: 0x00000000
.. 0xfa8002a94061    Signalling                      [unsigned char:Signalling]: 0x00000000
.. 0xfa8002a94061    TimerControlFlags               [unsigned char:TimerControlFlags]: 0x00000000
.. 0xfa8002a94062    CounterProfiling                [BitField(2-3):CounterProfiling]: 0x00000000
.. 0xfa8002a94062    CpuThrottled                    [BitField(0-1):CpuThrottled]: 0x00000000
.. 0xfa8002a94062    CycleProfiling                  [BitField(1-2):CycleProfiling]: 0x00000000
.. 0xfa8002a94062    Hand                            [unsigned char:Hand]: 0x00000058
.. 0xfa8002a94062    Reserved                        [BitField(3-8):Reserved]: 0x0000000B
.. 0xfa8002a94062    Size                            [unsigned char:Size]: 0x00000058
.. 0xfa8002a94062    ThreadControlFlags              [unsigned char:ThreadControlFlags]: 0x00000058
.. 0xfa8002a94063    ActiveDR7                       [BitField(0-1):ActiveDR7]: 0x00000000
.. 0xfa8002a94063    DebugActive                     [unsigned char:DebugActive]: 0x00000000
.. 0xfa8002a94063    DpcActive                       [unsigned char:DpcActive]: 0x00000000
.. 0xfa8002a94063    Expired                         [BitField(7-8):Expired]: 0x00000000
```
