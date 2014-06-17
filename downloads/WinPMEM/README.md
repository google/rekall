---
title: WinPMEM - A Windows Memory Acquisition Tool.
downloads:
   winpmem_1.6.0.exe: Signed Official WinPmem Acquisition tool
   winpmem_write_1.6.0.exe: Test WinPmem Acquisition tool with write support.
---
# WinPMEM - A Windows Memory Acquisition Tool.

Version 1.6.0

Michael Cohen <scudette@google.com>

This directory contains two binaries:

* winpmem_1.6.0.exe: The officially supported winpmem binary memory imager. This
  contains signed drivers for loading into 64 bit windows versions. The drivers
  support only read mode for forensic analysis. Write support is disabled.

* winpmem_write_1.6.0.exe: This is a binary with test signed drivers that also
  have write support enabled. These will not load on a regular windows machine!
  In order to use these drivers you will need to enable test mode signing in
  your kernel by typing in a cmd shell ```Bcdedit.exe -set TESTSIGNING ON``` and
  rebooting.
