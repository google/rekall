---
abstract: "Convert a profile from another program to the Rekall format.\n\n    The\
  \ Rekall profile format is optimized for loading at runtime. This plugin\n    produces\
  \ a Rekall profile from a variety of sources, including:\n\n    - Linux debug compiled\
  \ kernel module (see tool/linux/README)\n    - OSX Dwarfdump outputs.\n    "
args: {converter: 'The name of the converter to use. If not specified autoguess. (type:
    String)

    ', out_file: 'Path for output file. (type: String)

    ', profile_class: 'The name of the profile implementation to specify. If not specified,
    we autodetect. (type: String)

    ', source: 'Filename of profile to read. (type: String)

    '}
class_name: ConvertProfile
epydoc: rekall.plugins.tools.profile_tool.ConvertProfile-class.html
layout: plugin
module: rekall.plugins.tools.profile_tool
title: convert_profile
---

Rekall profiles are JSON files which contain information specific to a
particular software version. For example, Rekall requires a Linux Kernel profile
to be able to analyze a memory image of the Linux kernel.

The `convert_profile` plugin converts profiles other formats to the standard
JSON format used by Rekall. There are two main use cases:

1. If you have an old Volatility profile, this plugin will parse that.

2. When building a Linux kernel profile, the build system produces a debug
   enabled kernel module inside a Zip file. In this case you can use the
   `convert_profile` plugin to parse the DWARF stream from the debug module and
   produce the JSON file required.


The below example demonstrates how to build and convert a Linux profile locally
for live analysis:

```sh
rekall/tools/linux# make profile
make -C /usr/src/linux-headers-3.13.0-74-generic CONFIG_DEBUG_INFO=y M=`pwd` modules
make[1]: Entering directory `/usr/src/linux-headers-3.13.0-74-generic'
  Building modules, stage 2.
    MODPOST 2 modules
    make[1]: Leaving directory `/usr/src/linux-headers-3.13.0-74-generic'
    cp module.ko module_dwarf.ko
    zip "3.13.0-74-generic.zip" module_dwarf.ko /boot/System.map-3.13.0-74-generic /boot/config-3.13.0-74-generic
    updating: module_dwarf.ko (deflated 65%)
    updating: boot/System.map-3.13.0-74-generic (deflated 79%)
    updating: boot/config-3.13.0-74-generic (deflated 75%)

rekall/tools/linux# rekal convert_profile 3.13.0-74-generic.zip 3.13.0-74-generic.json
rekall/tools/linux# rekal --profile 3.13.0-74-generic.json -f /proc/kcore pslist
     task_struct           Name          PID    PPID   UID    GID        DTB              Start Time        Binary
     -------------- -------------------- ------ ------ ------ ------ -------------- ------------------------ ------
     0x8804285f0000 init                      1      0      0      0 0x000426592000     2016-01-29 12:50:31Z /sbin/init
     0x8804285f1800 kthreadd                  2      0      0      0 -                  2016-01-29 12:50:31Z -
     0x8804285f3000 ksoftirqd/0               3      2      0      0 -                  2016-01-29 12:50:31Z -
```
