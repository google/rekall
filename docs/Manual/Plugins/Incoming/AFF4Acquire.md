---
abstract: "Copy the physical address space to an AFF4 file.\n\n\n    NOTE: This plugin\
  \ does not require a working profile - unless the user also\n    wants to copy the\
  \ pagefile or mapped files. In that case we must analyze the\n    live memory to\
  \ gather the required files.\n    "
args: {also_mapped_files: 'Also get mapped or opened files (requires a profile) (type:
    Boolean)



    * Default: False', also_memory: 'Also acquire physical memory. If not specified
    we acquire physical memory only when no other operation is specified. (type: Boolean)

    ', also_pagefile: 'Also get the pagefile/swap partition (requires a profile) (type:
    Boolean)



    * Default: False', append: 'Append to the current volume.. (type: Boolean)



    * Default: False', compression: "The compression to use.\n\n* Valid Choices:\n\
    \    - snappy\n    - stored\n    - zlib\n", destination: 'The destination file
    to create. If not specified we write output.aff4 in current directory.


    * Default: output.aff4', files: 'Also acquire files matching the following globs.
    (type: ArrayStringParser)



    * Default: '}
class_name: AFF4Acquire
epydoc: rekall.plugins.tools.aff4acquire.AFF4Acquire-class.html
layout: plugin
module: rekall.plugins.tools.aff4acquire
title: aff4acquire
---
