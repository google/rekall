---
layout: docs
category: tools
title: The Pmem Memory acquisition suite.
author: Michael Cohen <scudette@gmail.com>
---

The Rekall project has maintained a set of open source memory acquisition tools
for a while now. After all, Memory acquisition is the first step in memory
analysis. Before any analysis can be done, we need to acquire the memory in the
first place. There are a number of commercial solutions to acquire memory, but
sadly open source solutions have been abandoned or not maintained (For example
win32dd has been a popular solution many years ago but has now been
commercialized and is no longer open source).

We believe in open source forensic tools to make testing and transparency
easier. We also believe that the availability of open source solutions spurs
further development in the field and enables choices.

That is the reason we feel an open source, well tested and capable forensic
memory acquisition tool is essential - we call it the Pmem suite of tools. The
pmem acquisition tool aims to provide a complete imaging solution for Windows,
Linux and OSX (OSXPmem is the only memory acquisition tool we are aware of,
which works on the latest version of OSX - 10.10.x - commercial or open source).

As we continue to develop Rekall into the most powerful memory forensic
platform, we developed the need to extend the acquisition tool. For example,
when Rekall gained the ability to analyze the windows pagefile, it became
important that the acquisition tool also collect the page file during
acquisition. Similarly we require the tool to collect critical system binaries.

We realized that we were in a unique position - not only are we developing the
most cutting edge memory analysis tool, but we are also developing the most
advanced memory acquisition tool. By being in control of the development process
of both tools, we can leverage the acquisition to assist the analysis, and
leverage the analysis to improve the acquisition.

For example, one of the first things that a memory analysis framework requires
is to derive the location of the page tables (dtb or CR3), the location of the
kernel image in memory (kaslr shift) or the exact version of the kernel. All of
these facts are immediately available to the acquisition tool at acquisition
time - if only there was a way for the acquisition tool to store this metadata
in the image, we would be able to analyze the image faster and more accurately.

Similarly, we often analyze memory images we acquired and discover that we left
some evidence behind during acquisition time - for example, if we try to dump
executables from memory, we might discover that many file mapped pages are not
present in the image. If only we could have acquired these files during the
acquisition time...

Our goal is to create a synergy between analysis and acquisition - collect as
much information as we can during the acquisition stage, driven by preliminary
analysis.

In order to do this preliminary triaging, we need to gain access to the live
physical memory of the system. Pmem is the only suite of memory acquisition
tools that allow for live forensics of the system they are running on. While
other acquisition tools are designed to dump memory image files from kernel
space, pmem tools generally pass data into user space and allow user space
processes direct access to physical memory.

It turns out that as physical memory sizes increase it takes so long to copy a
complete image out to disk, that smear is becoming a significant problem
(e.g. on very large servers). In this case live forensic analysis is the only
practical solution since the physical memory is examined over a very short
period of time (think running a pslist plugin which just follows a linked list).

We actually believe live memory analysis is the way forward.

## Image file format

Traditionally acquisition tools (like dd) simply wrote out a RAW format
image. This is by far the simplest image file format. In this format, the
physical address space is written byte for byte directly into the image file.

The nice thing about a raw image is that you don't need any special tools to read
it - every byte in the file corresponds to the same address in physical
memory. Some of the earliest memory analysis tools therefore only worked on RAW
images.

However there are a number of problems with RAW images:

- No ability to store sparse regions - all reserved regions must be padded in
  the image with zeros giving a larger image size. For example if you have 4GB
  of RAM, there will be about 1GB PCI hole reserved for DMA (e.g. video cards),
  so the RAW image is actually 5GB in size.

- No support for compression, encryption etc. This is a problem because
  sometimes using a fast compressor can actually produce higher throughput by
  minimizing IO.

- No support for additional metadata. This is required for the acquisition tool
  to tell us these critical constants we need for analysis!

- No support for embedding additional files, such as the pagefile, kernel image
  etc.

There are some other image file formats sometimes used but none of them have all
the required features:

The Microsoft Crashdump file, for example, is commonly used with windows images
- however this is a proprietary, undocumented file format with no support for
compression or embedding (although it supports some windows specific metadata)
it is also non-extensible. We do not recommend acquiring with this format
directly - if you need to analyze the image with the windows debugger we
recommend using the Rekall `raw2dmp` plugin to create a dump file later.

An ELF core file is the standard image format used by GDB and Linux when making
a core dump. This format allows the storage of sparse memory regions, but has
only limited support for extensible metadata. It is not possible to use this
format to collect related files (like the pagefile, kernel image etc). This
format is the default produced by versions of Rekall's pmem acquisition tools
prior to version 2.0. Certain virtualization tools like Virtual Box produce
memory images in this format so it can still be useful.

EWF is a compression format which is used by Encase. It offers the ability for
the image to be compressed but does not support sparse files, nor multiple
streams (at least the versions supported by the open source libewf tool).

Various ad-hoc imaging formats that are sometimes used. Rekall can read those if
you receive them in this format, but these format are not suitable for our
purposes (no compression or multiple files can be collected in the same image
file):

- Limes - an ad-hoc imaging format sometimes used on Linux. Does not really
  offer any advantages over an ELF core dump.
- HPAK - A proprietary format used in HBGary's tools.
- Mach-O - This is the binary format used on OSX. These kind of images used to
  be produced by the now defunct "Mac Memory Reader". Does not really offer any
  advantages over ELF core dumps.

After version 2.0 Rekall's pmem suite of acquisition tools have switched to the
AFF4 format for the default image format. AFF4 offers all the required features
and more:

- A peer reviewed open standard for storing digital images.

- Supports compression using the `Zlib` and `Snappy` compression formats (Snappy
  allows imaging at speeds greater than 300mb/s). This is really important to
  reduce memory smear.

- Supports storing arbitrary metadata via RDF information triples.

- Supports collecting multiple files (streams) in the same file. Thus we can
  collect binaries, pagefile as well as the physical memory the time of
  acquisition. Rekall can then use all these information sources seamlessly
  during analysis (i.e. no need to explicitly tell Rekall which is the
  pagefile).

The image file format is based on the standard Zip file format, with all the
advantages that brings, such as readily available tools for recovery of
corrupted image files, inspection, verification and manipulation of zip files.
Zip files are natively supported in almost every programming language -
decompressing an AFF4 stream can be done in 4 lines of python without the use of
a special AFF4 library (but the `pyaff4` library can also be used).

## AFF4 Volume overview.

We said that the AFF4 format is built on top of the standard ZIP format. This
means we can actually use the regular zip program to inspect an AFF4 volume.

The following is an image of a Windows Server 2003 system, acquired together
with the pagefile. As you can see it is just a zip file:

```shellsession
$ unzip -l images/Windows_Server-2003-R2_SP2-English-32Bit-Base-2015.02.11.aff4

Archive:  images/Windows_Server-2003-R2_SP2-English-32Bit-Base-2015.02.11.aff4
aff4://4928ef44-6579-496c-a53e-2ad34d98b7ed
  Length      Date    Time    Name
---------  ---------- -----   ----
      847  2015-03-10 00:50   information.turtle
       56  2015-03-10 00:50   PhysicalMemory/map
       64  2015-03-10 00:50   PhysicalMemory/idx
 12313883  2015-03-10 00:50   PhysicalMemory/data/00000031
     4048  2015-03-10 00:50   PhysicalMemory/data/00000031/index
        8  2015-03-10 00:50   c%3a/pagefile.sys/00000016
     4096  2015-03-10 00:49   PhysicalMemory/data/00000021/index
     4096  2015-03-10 00:49   PhysicalMemory/data/00000024/index
...
   166912  2015-03-10 00:50   c%3a/pagefile.sys/00000012
   166912  2015-03-10 00:50   c%3a/pagefile.sys/00000013
     4096  2015-03-10 00:50   c%3a/pagefile.sys/00000015/index
      204  2015-03-10 00:50   PhysicalMemory/information.yaml
        4  2015-03-10 00:50   c%3a/pagefile.sys/00000016/index
---------                     -------
278598663                     102 files
```

We can see that the AFF4 volume is denoted by a globally unique name
`aff4://4928ef44-6579-496c-a53e-2ad34d98b7ed`. This is called the AFF4 URN and
uniquely identifies this volume. The metadata is stored in this volume's archive
member called "information.turtle". We also see a number of streams - The
`PhysicalMemory` is the memory stream of the machine's physical memory,
"c%3a/pagefile.sys" is the stream corresponding with the machine's pagefile.

Lets examine the metadata stored in the information.turtle archive member:

```shellsession
$ unzip -p images/Windows_Server-2003-R2_SP2-English-32Bit-Base-2015.02.11.aff4 information.turtle
@base <aff4://4928ef44-6579-496c-a53e-2ad34d98b7ed> .
@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
@prefix aff4: <http://aff4.org/Schema#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .
@prefix memory: <http://aff4.org/Schema#memory/> .

</PhysicalMemory>
    aff4:category memory:physical ;
    aff4:stored <> ;
    a aff4:map .

</PhysicalMemory/data>
    aff4:chunk_size 32768 ;
    aff4:chunks_per_segment 1024 ;
    aff4:compression <https://www.ietf.org/rfc/rfc1950.txt> ;
    aff4:size 1073336320 ;
    aff4:stored <> ;
    a aff4:image .

</c:/pagefile.sys>
    aff4:category memory:pagefile ;
    aff4:chunk_size 32768 ;
    aff4:chunks_per_segment 1024 ;
    aff4:compression <https://www.ietf.org/rfc/rfc1950.txt> ;
    memory:pagefile_number 0 ;
    aff4:size 536870912 ;
    aff4:stored <> ;
    a aff4:image .
```

This shows us all the streams that exist in this volume encoded using the Turtle
RDF serialization. Each stream has a number of attributes (key value pairs). The
stream `aff4://4928ef44-6579-496c-a53e-2ad34d98b7ed/PhysicalMemory` has a
category of memory:physical (i.e. it is a physical memory image). It is
implemented as an `aff4:map` stream - i.e. this is a sparse stream which uses
`aff4://4928ef44-6579-496c-a53e-2ad34d98b7ed/PhysicalMemory/data` as backing
storage.

We can see the backing stream is an `aff4:image` typed stream with 32kb chunks,
1024 chunks per segment, using zlib compression.

Additionally we can see the pagefile is stored in a separate stream with a
category `memory:pagefile` (Rekall can then use the category to automatically
know how to use each stream).

# The PMEM suite of acquisition tools.

The Rekall project maintains a set of acquisition tools for the three supported
operating systems: Windows, Linux and OSX. Since version 2.0, the three imagers
have been merged into a single common framework. This means that you use them in
the same way, and they all produce the same type of AFF4 images.

All imagers share the common AFF4 imager architecture. This means you can use
all imagers for basic manipulation of all AFF4 volumes. Hence we will discuss
these common features here. Below we discuss some of the differences in the
implementations between the operating systems.

Lets consider the output from the --help command:

```shellsession
$ linpmem --help
USAGE:

   linpmem  [--elf] [-m] [-p </path/to/pagefile>] ...  [-V] [-d] [-v] [-t]
            [-i </path/to/file/or/device>] ...  [-e <string>] [-o
            </path/to/file>] [-c <zlib, snappy, none>] [--] [--version]
            [-h] </path/to/aff4/volume> ...


Where:

   --elf
     Normally pmem will produce an AFF4 volume but this option will force
     an ELF Core image file to be produced during acquisition. Note that
     this option is not compatible with the --input or --pagefile options
     because we can not write multiple streams into an ELF file.

     This option is mostly useful for compatibility with legacy memory
     analysis tools which do not understand AFF4 images.

     If this option is used together with the --export option we will
     export an ELF file from a stream within the AFF4 image.

   -m,  --acquire-memory
     Normally pmem will only acquire memory if the user has not asked for
     something else (like acquiring files, exporting etc). This option
     forces memory to be acquired. It is only required when the program is
     invoked with the --input, --export or other actionable flags.


   -p </path/to/pagefile>,  --pagefile </path/to/pagefile>  (accepted
      multiple times)
     Also capture the pagefile. Note that you must provide this option
     rather than e.g. '--input c:\pagefile.sys' because we can not normally
     read the pagefile directly. This option will use the sleuthkit to read
     the pagefile.

   -V,  --view
     View AFF4 metadata

   -d,  --debug
     Display debugging logging

   -v,  --verbose
     Display more verbose information

   -t,  --truncate
     Truncate the output file. Normally volumes and images are appended to
     existing files, but this flag forces the output file to be truncated
     first.

   -i </path/to/file/or/device>,  --input </path/to/file/or/device>
      (accepted multiple times)
     File to image. If specified we copy this file to the output volume
     located at --output. If there is no AFF4 volume on --output yet, we
     create a new volume on it.

     This can be specified multiple times with shell expansion. e.g.:

     -i /bin/*

   -e <string>,  --export <string>
     Name of the stream to export. If specified we try to open this stream
     and write it to the --output file. Note that you will also need to
     specify an AFF4 volume path to load so we know where to find the
     stream. Specifying a relative URN implies a stream residing in a
     loaded volume. E.g.

     -e /dev/sda -o /tmp/myfile my_volume.aff4

   -o </path/to/file>,  --output </path/to/file>
     Output file to write to. If the file does not exist we create it.

   -c <zlib, snappy, none>,  --compression <zlib, snappy, none>
     Type of compression to use (default zlib).

   --,  --ignore_rest
     Ignores the rest of the labeled arguments following this flag.

   --version
     Displays version information and exits.

   -h,  --help
     Displays usage information and exits.

   </path/to/aff4/volume>  (accepted multiple times)
     These AFF4 Volumes will be loaded and their metadata will be parsed
     before the program runs.

     Note that this is necessary before you can extract streams with the
     --export flag.


   The LinuxPmem memory imager.  Copyright 2014 Google Inc.
```

## Inspecting an AFF4 Volume.

The tool can examine an AFF4 volume as we have seen previously. It actually
loads the provided AFF4 volume and outputs a common view of all known objects.

```shellsession
$ linpmem -V images/Windows_Server-2003-R2_SP2-English-32Bit-Base-2015.02.11.aff4
@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
@prefix aff4: <http://aff4.org/Schema#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .
@prefix memory: <http://aff4.org/Schema#memory/> .

<aff4://4928ef44-6579-496c-a53e-2ad34d98b7ed/PhysicalMemory>
    aff4:category memory:physical ;
    aff4:stored <aff4://4928ef44-6579-496c-a53e-2ad34d98b7ed> ;
    a aff4:map .

<aff4://4928ef44-6579-496c-a53e-2ad34d98b7ed/PhysicalMemory/data>
    aff4:chunk_size 32768 ;
    aff4:chunks_per_segment 1024 ;
    aff4:compression <https://www.ietf.org/rfc/rfc1950.txt> ;
    aff4:size 1073336320 ;
    aff4:stored <aff4://4928ef44-6579-496c-a53e-2ad34d98b7ed> ;
    a aff4:image .

<aff4://4928ef44-6579-496c-a53e-2ad34d98b7ed/c:/pagefile.sys>
    aff4:category memory:pagefile ;
    aff4:chunk_size 32768 ;
    aff4:chunks_per_segment 1024 ;
    aff4:compression <https://www.ietf.org/rfc/rfc1950.txt> ;
    memory:pagefile_number 0 ;
    aff4:size 536870912 ;
    aff4:stored <aff4://4928ef44-6579-496c-a53e-2ad34d98b7ed> ;
    a aff4:image .

<file:///home/scudette/projects/workshop/02-What_is_memory/images/Windows_Server-2003-R2_SP2-English-32Bit-Base-2015.02.11.aff4>
    aff4:contains <aff4://4928ef44-6579-496c-a53e-2ad34d98b7ed> .
```

## Extracting a stream from an AFF4 volume.

We can extract one of the streams to a file. This is sometimes useful for using
tools which do not support AFF4 natively. For example, we can extract the
pagefile into the /tmp/ directory:

```shellsession
$ linpmem --export /c:/pagefile.sys --output /tmp/pagefile.sys images/Windows_Server-2003-R2_SP2-English-32Bit-Base-2015.02.11.aff4

Extracting aff4://4928ef44-6579-496c-a53e-2ad34d98b7ed/c:/pagefile.sys into file:///tmp/pagefile.sys
 Reading 0xa00000  10MiB / 512MiB 0MiB/s
 Reading 0x5000000  80MiB / 512MiB 266MiB/s
 Reading 0xc800000  200MiB / 512MiB 474MiB/s
 Reading 0x15e00000  350MiB / 512MiB 586MiB/s
 Reading 0x19a00000  410MiB / 512MiB 236MiB/s
 Reading 0x1d600000  470MiB / 512MiB 216MiB/s
```

## Adding a new stream to an AFF4 volume.

By default the AFF4 imager tools append streams to existing volumes, rather than
overwrite the volume. Therefore it is easy to add additional files after the
acquisition is complete to the acquired volume. It is also possible to specify
shell globs to add multiple files to the volume. In this sense, the AFF4 volume
acts more like a zip container - you can just keep on adding new files.

This is handy if initial analysis reveals some suspected files which we can
acquire immediately into the AFF4 volume after the memory is captured. The -t
flag explicitly allows pmem to truncate the output file (this will delete all
current content of the volume).

For example, the following will add files in /bin/* to the AFF4 volume (without
overwriting it).

```shellsession
$ linpmem -i /bin/* -o /tmp/test.aff4

Adding /bin/bash as file:///bin/bash
Adding /bin/bsd-csh as file:///bin/bsd-csh
Adding /bin/bunzip2 as file:///bin/bunzip2
Adding /bin/busybox as file:///bin/busybox
Adding /bin/bzcat as file:///bin/bzcat
Adding /bin/bzcmp as file:///bin/bzcmp
Adding /bin/bzdiff as file:///bin/bzdiff
```

# The WinPmem acquisition tool.

On Windows, one must insert a signed driver in order to gain access to physical
memory. WinPmem from version 2.0 is built on top of the AFF4 imager technology,
and is packaged bundled with the appropriate memory drivers. Since AFF4 volumes
utilize zip file, as their underlying storage format, it is possible to append
an AFF4 volume to the end of any other file type. The WinPmem acquisition tool
utilizes this property to simply package all needed drivers and tools together
with the executable itself - using the AFF4 format.

We typically package with winpmem the 64 bit and 32 bit windows kernel drivers,
as well as a copy of fcat.exe from the sleuthkit . This tool is used to provide
access to the locked pagefiles. (Note that if you just want to extract the
drivers - e.g. to use in another project you can just unzip the winpmem
executable).

If no other operation was specified, WinPmem will immediately image memory and
also acquire certain files, such as drivers and the kernel image. These are
useful to preserve the exact versions of binaries running on the system at the
time of the acquisition.

By default WinPmem uses a technique called PTE Remapping to acquire memory. This
technique was originally developed in order to bypass potential malware hooking
the APIs normally used for acquisition. After much use we found that the
technique is in fact more stable than using the APIs and it is actually the only
reliable way that access to physical memory is achievable on OSX. We therefore
decided to make this the default acquisition mode on both Windows and OSX.

To acquire memory all one needs to do is to specify the output volume:
```shellsession
C:\Users\mic>winpmem_2.0.1.exe -o test.aff4
Driver Unloaded.
CR3: 0x0000187000
 2 memory ranges:
Start 0x00001000 - Length 0x0009E000
Start 0x00100000 - Length 0x3FEF0000
Dumping Range 0 (Starts at 1000)
Dumping Range 1 (Starts at 100000)
Adding C:\Windows\SysNative\drivers/1394bus.sys as file:///C:/Windows/SysNative/drivers/1394bus.sys
Adding C:\Windows\SysNative\drivers/1394ohci.sys as file:///C:/Windows/SysNative/drivers/1394ohci.sys
Adding C:\Windows\SysNative\drivers/acpi.sys as file:///C:/Windows/SysNative/drivers/acpi.sys
Adding C:\Windows\SysNative\drivers/acpipmi.sys as file:///C:/Windows/SysNative/drivers/acpipmi.sys
Adding C:\Windows\SysNative\drivers/adp94xx.sys as file:///C:/Windows/SysNative/drivers/adp94xx.sys
Adding C:\Windows\SysNative\drivers/adpahci.sys as file:///C:/Windows/SysNative/drivers/adpahci.sys
....
Adding C:\Windows\SysNative\drivers/WUDFPf.sys as file:///C:/Windows/SysNative/drivers/WUDFPf.sys
Adding C:\Windows\SysNative\drivers/WUDFRd.sys as file:///C:/Windows/SysNative/drivers/WUDFRd.sys
Driver Unloaded.
```

Note that by default the imager also captures the kernel and driver
binaries. You can also choose the snappy compression (`--compression snappy`)
for a faster compression algorithm.

Now we can use rekall to analyze this image:
```shellsession
C:\Users\mic>"c:\Program Files\Rekall\rekal.exe" -f test.aff4

----------------------------------------------------------------------------
The Rekall Memory Forensic framework 1.3.2 (Dammastock).

"We can remember it for you wholesale!"

This program is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License.

See http://www.rekall-forensic.com/docs/Manual/tutorial.html to get started.
----------------------------------------------------------------------------
[1] test.aff4 15:56:05> pslist
  _EPROCESS            Name          PID   PPID   Thds    Hnds    Sess  Wow64           Start
-------------- -------------------- ----- ------ ------ -------- ------ ------ ------------------------
0xfa8000c9f040 System                   4      0     79      528      - False  2015-04-24 12:12:36+0000
0xfa8000ea3340 SearchProtocol         208   2336      7      284      0 False  2015-04-24 13:37:11+0000
0xfa8001d229f0 smss.exe               228      4      2       29      - False  2015-04-24 12:12:36+0000
```

# The LinPmem acquisition tool.

By default, the linpmem acquisition tool uses the `/proc/kcore` device to
acquire physical memory. This device must be enabled during kernel configuration
but we found that in most distributions the device is already enabled.

# The OSXPmem acquisition tool

OSXPmem has recently been updated with a new driver written by Adam Sindelar
called `MacPmem.kext`. The new driver is more stable and works on all versions
of OSX including the most recent 10.10 series. The new driver presents two
devices:

1. The `/dev/pmem` device is the raw physical memory device - reading from this
   device allows userspace applications (running as root) to read physical
   memory - e.g. Rekall itself can be used for live analysis.

2. The `/dev/pmem_info` device presents information collected by the driver
   about the system - such as the EFI ranges, kernel slide and other critical
   parameters.

The following example illustrates how we can image memory on OSX. First we must
elevate to the root user, then unzip the contents of the `osxpmem.zip`
distribution. Note that the `MacPmem.kext` directory and its content must be
owned by root with group wheel, otherwise `kextload` will refuse to insert the
kernel module.

Next we simply load the driver using `kextload` and run the acquisition tool to
create the AFF4 volume.

```shellsession
$ sudo bash
Password:
# unzip osxpmem_2.0.1.zip
Archive:  osxpmem_2.0.1.zip
   creating: osxpmem.app/
   creating: osxpmem.app/libs/
  inflating: osxpmem.app/libs/libaff4.0.dylib
  inflating: osxpmem.app/libs/libcrypto.1.0.0.dylib
  inflating: osxpmem.app/libs/libcurl.4.dylib
  inflating: osxpmem.app/libs/libgflags.2.dylib
  inflating: osxpmem.app/libs/libglog.0.dylib
  inflating: osxpmem.app/libs/libiconv.2.dylib
  inflating: osxpmem.app/libs/libidn.11.dylib
  inflating: osxpmem.app/libs/libintl.8.dylib
  inflating: osxpmem.app/libs/liblzma.5.dylib
  inflating: osxpmem.app/libs/libpcre++.0.dylib
  inflating: osxpmem.app/libs/libpcre.1.dylib
  inflating: osxpmem.app/libs/libraptor2.0.dylib
  inflating: osxpmem.app/libs/libsnappy.1.dylib
  inflating: osxpmem.app/libs/libssl.1.0.0.dylib
  inflating: osxpmem.app/libs/liburiparser.1.dylib
  inflating: osxpmem.app/libs/libuuid.16.dylib
  inflating: osxpmem.app/libs/libxml2.2.dylib
  inflating: osxpmem.app/libs/libxslt.1.dylib
  inflating: osxpmem.app/libs/libz.1.dylib
   creating: osxpmem.app/MacPmem.kext/
   creating: osxpmem.app/MacPmem.kext/Contents/
   creating: osxpmem.app/MacPmem.kext/Contents/_CodeSignature/
  inflating: osxpmem.app/MacPmem.kext/Contents/_CodeSignature/CodeResources
  inflating: osxpmem.app/MacPmem.kext/Contents/Info.plist
   creating: osxpmem.app/MacPmem.kext/Contents/MacOS/
  inflating: osxpmem.app/MacPmem.kext/Contents/MacOS/MacPmem
  inflating: osxpmem.app/osxpmem
  inflating: osxpmem.app/README.md
# kextload osxpmem.app/MacPmem.kext/
# ./osxpmem.app/osxpmem -o /tmp/test.aff4
Imaging memory
E0424 16:26:04.297508 2091074320 osxpmem.cc:138] Range 0 581632
E0424 16:26:04.297526 2091074320 osxpmem.cc:138] Range 589824 65536
E0424 16:26:04.297534 2091074320 osxpmem.cc:138] Range 1048576 535822336
E0424 16:26:04.297541 2091074320 osxpmem.cc:138] Range 538968064 534790144
E0424 16:26:04.297549 2091074320 osxpmem.cc:138] Range 1073762304 1257820160
E0424 16:26:04.297555 2091074320 osxpmem.cc:138] Range 2332028928 4096
E0424 16:26:04.297562 2091074320 osxpmem.cc:138] Range 4294967296 14753464320
 Reading 0x19100000  400MiB / 511MiB 55MiB/s
Adding /mach_kernel as file:///mach_kernel77MiB/s
Adding /dev/pmem_info as file:///dev/pmem_info
Adding /System/Library/Extensions/ALF.kext/Contents/MacOS/ALF as file:///System/Library/Extensions/ALF.kext/Contents/MacOS/ALF
Adding /System/Library/Extensions/ALF.kext/Contents/Resources/Dutch.lproj/ as file:///System/Library/Extensions/ALF.kext/Contents/
Resources/Dutch.lproj/
Adding /System/Library/Extensions/ALF.kext/Contents/Resources/English.lproj/ as file:///System/Library/Extensions/ALF.kext/Content
s/Resources/English.lproj/
...
# cat /dev/pmem_info | head
%YAML 1.2
---
meta:
  pmem_api_version: 1
  cr3: 14860288073
  dtb_off: 14860288000
  phys_mem_size: 17179869184
  pci_config_space_base: 3758096384
  mmap_poffset: 107778048
  mmap_desc_version: 1
  mmap_size: 13776
  mmap_desc_size: 48
  kaslr_slide: 62914560
  kernel_poffset: 63963136
  kernel_version: "Darwin Kernel Version 13.4.0: Wed Mar 18 16:20:14 PDT 2015; root:xnu-2422.115.14~1/RELEASE_X86_64"
records:
  - purpose: "(PCI) IGPU/0"
    type: "pci_range"
    pci_type: "PCIUnknownMemory"
    start: 4768923648
    length: 4194304
    hw_informant: false
```

As usual live analysis can be performed by simply specifying the `/dev/pmem`
device for Rekall.