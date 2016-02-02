---
abstract: "Copy the physical address space to an AFF4 file.\n\n\n    NOTE: This plugin\
  \ does not required a working profile - unless the user also\n    wants to copy\
  \ the pagefile or mapped files. In that case we must analyze the\n    live memory\
  \ to gather the required files.\n    "
args: {also_files: 'Also get mapped or opened files (requires a profile) (type: Boolean)



    * Default: False', also_pagefile: 'Also get the pagefile/swap partition (requires
    a profile) (type: Boolean)



    * Default: False', compression: "The compression to use.\n\n* Valid Choices:\n\
    \    - snappy\n    - stored\n    - zlib\n", destination: 'The destination file
    to create. If not specified we write output.aff4 in current directory.


    * Default: output.aff4'}
class_name: AFF4Acquire
epydoc: rekall.plugins.tools.aff4acquire.AFF4Acquire-class.html
layout: plugin
module: rekall.plugins.tools.aff4acquire
title: aff4acquire
---
