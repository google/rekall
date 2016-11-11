---
abstract: "Convert the physical address space to a crash dump.\n\n    The Windows\
  \ debugger (Windbg) works only with memory dumps stored\n    in the proprietary\
  \ 'crashdump' file format. This file format\n    contains the following features:\n\
  \n    1) Physical memory ranges are stored in a sparse way - there is a\n      \
  \ 'Runs' table which specifies the mapping between the physical\n       offset and\
  \ the file offset of each page. This allows the format\n       to omit unmapped\
  \ regions (unlike raw format which must pad them\n       with zero to maintain alignment).\n\
  \n    2) The crash dump header contains metadata about the\n       image. Specifically,\
  \ the header contain a copy of the Kernel\n       Debugger Data Block (AKA the KDBG).\
  \ This data is used to\n       bootstrap the windows debugger by providing critical\
  \ initial\n       hints to the debugger.\n\n    Since the KDBG block is created\
  \ at system boot and never used\n    (until the crash dump is written) it is trivial\
  \ for malware to\n    overwrite it - making it really hard for responders since\
  \ windbg\n    will not be able to read the file. In later versions of windows,\n\
  \    the kdbg is also obfuscated (See the function \"nt!KdCopyDataBlock\"\n    which\
  \ decrypts it.).\n\n    Rekall itself does not use the KDBG block any more, although\
  \ older\n    memory forensic tools still do use it. Rekall instead relies on\n \
  \   accurate debugging symbols to locate critical kernel data\n    structures, reducing\
  \ the level of trust we place on the image\n    itself (so Rekall is more resilient\
  \ to manipulation).\n\n    In order to ensure that the windows debugger is able\
  \ to read the\n    produced crash dump, we recreate the kernel debugger block from\n\
  \    the symbol information we already have.\n\n    NOTE: The crashdump file format\
  \ can be deduced by:\n\n    dis 'nt!IoFillDumpHeader'\n\n    This is the reference\
  \ for this plugin.\n    "
args: {destination: 'The destination path to write the crash dump. (type: String)

    ', rebuild: 'Rebuild the KDBG data block. (type: Boolean)

    ', verbosity: 'An integer reflecting the amount of desired output: 0 = quiet,
    10 = noisy. (type: IntParser)



    * Default: 1'}
class_name: Raw2Dump
epydoc: rekall.plugins.windows.crashinfo.Raw2Dump-class.html
layout: plugin
module: rekall.plugins.windows.crashinfo
title: raw2dmp
---

The Windows debugger (Windbg) works only with memory dumps stored
in the proprietary 'crashdump' file format. This file format
contains the following features:

1. Physical memory ranges are stored in a sparse way - there is a
   `Runs` table which specifies the mapping between the physical
   offset and the file offset of each page. This allows the format
   to omit unmapped regions (unlike raw format which must pad them
   with zero to maintain alignment).

2. The crash dump header contains metadata about the
   image. Specifically, the header contain a copy of the Kernel
   Debugger Data Block (AKA the **KDBG**). This data is used to
   bootstrap the windows debugger by providing critical initial
   hints to the debugger.

Since the **KDBG** block is created at system boot and never used (until the
crash dump is written) it is trivial for malware to overwrite it - making it
really hard for responders since windbg will not be able to read the file. In
later versions of windows, the KDBG is also obfuscated (See the function
`nt!KdCopyDataBlock` which decrypts it.).

Rekall itself does not use the **KDBG** block any more, although older memory
forensic tools still do use it. Rekall instead relies on accurate debugging
symbols to locate critical kernel data structures, reducing the level of trust
we place on the image itself (so Rekall is more resilient to manipulation).

In order to ensure that the windows debugger is able to read the produced crash
dump, we recreate the kernel debugger block from the symbol information we
already have.

### Notes:

1. The crashdump file format can be deduced by:
   ```
   dis 'nt!IoFillDumpHeader'
   ```
   This is the reference for this plugin.

2. This plugin is really only useful in order to produce an image compatible
   with the windows debugger for the purpose of further investigation by the
   debugger. If you find that the windows debugger has a useful feature that
   Rekall does not have, please let us know so we can implement it in Rekall. We
   intend to replace the use of the windows debugger in digital forensics.
