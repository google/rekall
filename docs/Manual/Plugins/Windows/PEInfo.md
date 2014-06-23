---
layout: plugin
title: peinfo
abstract: |
  Print information about a PE binary.

epydoc: rekall.plugins.windows.procinfo.PEInfo-class.html
args:
  image_base: 'The base of the image.'
  executable: 'If provided we create an address space from this file.'
  address_space: 'The address space to use.'
  verbosity: 'Add more output.'

---

The **peinfo** plugin examines a PE file mapped into memory and displays a rich
variety of information about it:

* Metadata about the file (architecture, build date etc)
* The PDB guid for the file.
* The list of sections and where they are mapped into the virtual address space
* The import directory.
* The export directory.
* A version resource strings that might exist in the executable.

### Notes

1. This plugin depends on having a valid mapped PE header into memory. Sometimes
   this is not the case, since under memory pressure the kernel will unmapped
   the PE headers (since they are not needed after loading).

2. This plugin also works on disk files (PE executable). Simply pass a filename
   parameter to have it print information about external files.


### Sample output

```
win8.1.raw 15:11:02> peinfo "nt"
-------------------> peinfo("nt")
Attribute            Value
-------------------- -----
Machine              IMAGE_FILE_MACHINE_AMD64
TimeDateStamp        2013-09-14 08:23:16+0000
Characteristics      IMAGE_FILE_EXECUTABLE_IMAGE, IMAGE_FILE_LARGE_ADDRESS_AWARE
GUID/Age             FD3D00D28EDC4527BB922BCC0509D2851
PDB                  ntkrnlmp.pdb
MajorOperatingSystemVersion 6
MinorOperatingSystemVersion 3
MajorImageVersion    6
MinorImageVersion    3
MajorSubsystemVersion 6
MinorSubsystemVersion 3

Sections (Relative to 0xF802D3019000):
Perm Name          VMA            Size
---- -------- -------------- --------------
xr-  .text    0x000000001000 0x00000028d600
xr-  NONPAGED 0x00000028f000 0x000000000200
xr-  POOLCODE 0x000000290000 0x000000002800
-rw  .data    0x000000293000 0x00000000be00
-r-  .reloc   0x000000778000 0x000000008e00
...

Data Directories:
-                                             VMA            Size
---------------------------------------- -------------- --------------
IMAGE_DIRECTORY_ENTRY_EXPORT             0xf802d36ab000 0x0000000135ff
IMAGE_DIRECTORY_ENTRY_IMPORT             0xf802d335b728 0x00000000012c
IMAGE_DIRECTORY_ENTRY_RESOURCE           0xf802d375f000 0x000000031d20
IMAGE_DIRECTORY_ENTRY_EXCEPTION          0xf802d331c000 0x00000003ed6c
IMAGE_DIRECTORY_ENTRY_SECURITY           0xf802d3725e00 0x000000002158
IMAGE_DIRECTORY_ENTRY_BASERELOC          0xf802d3791000 0x000000003cd4
IMAGE_DIRECTORY_ENTRY_DEBUG              0xf802d301a100 0x000000000038
IMAGE_DIRECTORY_ENTRY_COPYRIGHT          0x000000000000 0x000000000000
IMAGE_DIRECTORY_ENTRY_GLOBALPTR          0x000000000000 0x000000000000
IMAGE_DIRECTORY_ENTRY_TLS                0x000000000000 0x000000000000
IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG        0xf802d3033f20 0x000000000094
IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT       0x000000000000 0x000000000000
IMAGE_DIRECTORY_ENTRY_IAT                0xf802d335b000 0x000000000728
IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT       0x000000000000 0x000000000000
IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR     0x000000000000 0x000000000000
IMAGE_DIRECTORY_ENTRY_RESERVED           0x000000000000 0x000000000000

Import Directory (Original):
Name                                               Ord
-------------------------------------------------- -----
ext-ms-win-ntos-werkernel-l1-1-0.dll!WerLiveKernelCloseHandle 1
ext-ms-win-ntos-werkernel-l1-1-0.dll!WerLiveKernelOpenDumpFile 4
ext-ms-win-ntos-werkernel-l1-1-0.dll!WerLiveKernelCancelReport 0
ext-ms-win-ntos-werkernel-l1-1-0.dll!WerLiveKernelInitSystem 3
...
msrpc.sys!MesDecodeBufferHandleCreate              11
msrpc.sys!NdrMesTypeDecode3                        45

Export Directory:
    Entry      Stat Ord   Name
-------------- ---- ----- --------------------------------------------------
0xf802d30ed1f4 M    3     ntoskrnl.exe!AlpcGetHeaderSize (nt!AlpcGetHeaderSize)
0xf802d30ed080 M    4     ntoskrnl.exe!AlpcGetMessageAttribute (nt!AlpcGetMessageAttribute)
0xf802d30ed19c M    5     ntoskrnl.exe!AlpcInitializeMessageAttribute (nt!AlpcInitializeMessageAttribute)
0xf802d36a4004 -    6     ntoskrnl.exe!BgkDisplayCharacter (nt!BgkDisplayCharacter)
0xf802d36a40b8 -    7     ntoskrnl.exe!BgkGetConsoleState (nt!BgkGetConsoleState)
0xf802d36a40e0 -    8     ntoskrnl.exe!BgkGetCursorState (nt!BgkGetCursorState)
0xf802d36a4108 -    9     ntoskrnl.exe!BgkSetCursor (nt!BgkSetCursor)
0xf802d31d23c8 M    10    ntoskrnl.exe!CcAddDirtyPagesToExternalCache (nt!CcAddDirtyPagesToExternalCache)
0xf802d3106888 M    11    ntoskrnl.exe!CcCanIWrite (nt!CcCanIWrite)
...
```