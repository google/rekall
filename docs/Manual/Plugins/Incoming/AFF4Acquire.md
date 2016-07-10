---
abstract: "Copy the physical address space to an AFF4 file.\n\n\n    NOTE: This plugin\
  \ does not require a working profile - unless the user also\n    wants to copy the\
  \ pagefile or mapped files. In that case we must analyze the\n    live memory to\
  \ gather the required files.\n    "
args: {also_mapped_files: 'Also get mapped or opened files (requires a profile) (type:
    Boolean)

    ', also_memory: 'Also acquire physical memory. If not specified we acquire physical
    memory only when no other operation is specified. (type: Boolean)



    * Default: auto', also_pagefile: 'Also get the pagefile/swap partition (requires
    a profile) (type: Boolean)

    ', append: 'Append to the current volume. (type: Boolean)



    * Default: False', compression: "The compression to use. (type: String)\n\n\n\
    * Valid Choices:\n    - snappy\n    - stored\n    - zlib\n\n\n* Default: snappy",
  destination: 'The destination file to create.  (type: String)

    ', files: 'Also acquire files matching the following globs. (type: ArrayStringParser)

    ', gce_credentials: 'The GCE service account credentials to use. (type: String)

    ', gce_credentials_path: 'A path to the GCE service account credentials to use.
    (type: String)

    ', max_file_size: 'Maximum file size to acquire. (type: IntParser)



    * Default: 104857600'}
class_name: AFF4Acquire
epydoc: rekall.plugins.tools.aff4acquire.AFF4Acquire-class.html
layout: plugin
module: rekall.plugins.tools.aff4acquire
title: aff4acquire
---
