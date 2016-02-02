---
abstract: Copy the physical address space to an EWF file.
args: {destination: The destination file to create. If not specified we write output.E01
    in current directory.}
class_name: EWFAcquire
epydoc: rekall.plugins.tools.ewf.EWFAcquire-class.html
layout: plugin
module: rekall.plugins.tools.ewf
title: ewfacquire
---

Rekall supports many different image formats. One of the popular formats is the
EWF or E01 formats. It is a compressible format for forensic images.

The `ewfacquire` plugin will copy the physical address space into an EWF
file. This can be used to acquire memory (e.g. when Rekall is used in live mode)
or to convert a memory image from another format to EWF format.

Note that the EWF format is not an open format. The variant written by Rekall is
not necessarily interchangeable with other implementations. We usually recommend
using `aff4acquire` over `ewfacquire` because the AFF4 format can contain
multiple streams and can also keep important metadata.

```text
[1] win7.elf 23:02:22> ewfacquire destination="/tmp/test.E01"
---------------------> ewfacquire(destination="/tmp/test.E01")
 Writing 352Mb
```
