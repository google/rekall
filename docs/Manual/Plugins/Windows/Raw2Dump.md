---
layout: plugin
title: raw2dmp
abstract: |
  Convert the physical address space to a crash dump.

epydoc: rekall.plugins.windows.crashinfo.Raw2Dump-class.html
args:
  destination: 'The destination path to write the crash dump.'
  rebuild: 'Rebuild the KDBG data block.'

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
later versions of windows, the kdbg is also obfuscated (See the function
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
   Rekall does not have, please let up know so we can implement it in Rekall. We
   intend to replace the use of the windows debugger in digital forensics.
