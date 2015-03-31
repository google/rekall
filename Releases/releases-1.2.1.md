---
layout: download
menuitem: Releases
title: Version 1.2.1 Col de la Croix.
order: 2
---

# Rekall Memory Forensic Releases

## Version 1.2.1 Col de la Croix

This release just made it in time for Christmas! Enjoy!

### Release Highlights

Filesystems
:  For the first time Rekall includes experimental support for analysis of
   traditional Disk images. This release includes a full featured parser for
   NTFS. Some interesting plugins:

* `fls`: List files in the filesystem.
* `istat`: Displays information about an MFT entry.
* `idump`: hexdump an attribute or stream.
* `iexport`: Exports a file from the NTFS.

Windows
:  This release includes full support for acquisition and analysis of the
   windows page file. Some interesting plugins include:

* `pagefiles`: Lists the currently active page files and their locations.
* `vadmap`: Displays each page in the VAD and resolves its location in physical
    memory (or the page file).
* `vtop`: This plugin was expanded to display where virtual pages are actually
    backed by the page file.
* `dumpfiles`: This plugin was finally implemented in Rekall.
* `inspect_heap`: Experimental support for heap enumeration on Win7 x64 allows
  enumeration of userspace heap allocation (e.g. malloc()).
    * `dns_cache`: This is also used to enumerate the dns cache by inspecting
      heap allocations.

OSX
: This release adds a functional Entity layer. Currently confined to OSX
  analysis. Entities are a kind of query language for memory artifacts.
  Some useful plugins:

* `find`: Search for entities based on a query.
* `analyze`: Analyze the internal query optimizer's collectors that will be run in
  response to a query.
* Most other plugins are rewritten in terms of entities (e.g. `lsof`, `netstat` etc.)

Linux
: This release brings a dedicated userspace imager to Linux. The `lmap` tool was
  expanded to write ELF core dump files and acquire directly from `/proc/kcore`,
  if the target system supports it (in this case no kernel module is needed).

* MIPS address space added for support on Big Endian Machines.

Misc
: Rekall can now read and write EWF files natively. There have been many
  performance and stability improvements too.

* `ewfacquire`: Rekall can be used to acquire memory efficiently, writing an EWF
  compressed file (with an embedded ELF file).
* The Profile repository is now cached locally to make subsequent runs faster.