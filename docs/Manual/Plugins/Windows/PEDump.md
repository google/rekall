---
layout: plugin
title: pedump
abstract: |
  Dump a PE binary from memory.

epydoc: rekall.plugins.windows.procdump.PEDump-class.html
args:
  address_space: ''
  image_base: 'The address of the image base (dos header).'
  out_fd: ''
  out_file: 'The file name to write.'
  pid: 'One or more pids of processes to select.'
  eprocess: 'Kernel addresses of eprocess structs.'
  phys_eprocess: 'Physical addresses of eprocess structs.'
  proc_regex: 'A regex to select a process by name.'
  method: 'Method to list processes (Default uses all methods).'

---

Windows executable files (PE Files) are mapped into memory from disk. This
plugin can dump arbitrary PE files from memory (whether they are executables,
DLLs, kernel modules etc). All we require is the PE file's mapped base addresses
(i.e. the location in the virtual address space where the MZ header resides.

The image_base offset can be specified using a named address as usual. So for
example, to specify a kernel module it is sufficient to just name it
(e.g. pedump "nt" - will dump the kernel image).

This plugin is used by the **dlldump**, **moddump**, **procdump** etc plugins.

### Note

1. In order to dump any PE file from memory we need the PE header to be memory
   resident. Often this is not the case, and the header is flushed out of
   virtual memory. In this case it is still possible to dump parts of the PE
   image using the [vaddump](VADDump.html) plugin.

2. When dumping any binary from memory, it is not usually a perfect binary
   (i.e. you can not just run it). This is because the Import Address Table
   (IAT) reflects the patched version in memory and some pages may be
   missing. The resultant binary is probably only useful to analyses using a
   tool like IDA pro.

