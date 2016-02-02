---
abstract: Copies a physical address space out as a raw DD image
args: {output-image: Filename to write output image.}
class_name: ImageCopy
epydoc: rekall.plugins.imagecopy.ImageCopy-class.html
layout: plugin
module: rekall.plugins.imagecopy
title: imagecopy
---

Rekall supports many different image formats. Image formats such as AFF4 and EWF
are very convenient for long term storage and archiving of images. However, some
other memory analysis tools do not support such a rich selection of image
formats and might not be able to directly analyze some of these formats.

Sometimes we might want to verify something with another tool, and the RAW image
format seems to be most widely supported. The `imagecopy` plugin copies the
current physical address space into a RAW file. It pads sparse regions with NULL
bytes.

Note that RAW images can not contain multiple streams (like the pagefile), nor
do they support any metadata (such as registers). Hence the RAW image is vastly
inferior. We do not recommend actually acquiring the image using the RAW format
in the first place (use AFF4 or ELF). However, if Rekall is run in live mode,
the `imagecopy` plugin will produce a RAW image of live memory.

In the following example we convert an EWF image to raw so Volatility can read
it:

```text
[1] win7.elf.E01 23:36:57> imagecopy "/tmp/foo.raw"
---------------------> imagecopy("/tmp/foo.raw")
Range 0x0 - 0x2cb00000
Range 0xe0000000 - 0x1000000
Range 0xf0400000 - 0x400000
Range 0xf0800000 - 0x4000
Range 0xffff0000 - 0x10000
               Out<27> Plugin: imagecopy

[1] win7.elf.E01 23:38:06> !python /home/scudette/projects/volatility/vol.py --profile Win7SP1x64 -f /tmp/foo.raw pslist
Volatility Foundation Volatility Framework 2.5
Offset(V)          Name                    PID   PPID   Thds     Hnds   Sess  Wow64 Start                          Exit
------------------ -------------------- ------ ------ ------ -------- ------ ------ ------------------------------ ------------------------------
0xfffffa80008959e0 System                    4      0     84      511 ------      0 2012-10-01 21:39:51 UTC+0000
0xfffffa8001994310 smss.exe                272      4      2       29 ------      0 2012-10-01 21:39:51 UTC+0000
0xfffffa8002259060 csrss.exe               348    340      9      436      0      0 2012-10-01 21:39:57 UTC+0000
```
