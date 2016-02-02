---
abstract: "A plugin to search for the Directory Table Base for windows systems.\n\n\
  \    There are a number of ways to find the DTB:\n\n    - Scanner method: Scans\
  \ the image for a known kernel process, and read the\n      DTB from its Process\
  \ Environment Block (PEB).\n\n    - Get the DTB from the KPCR structure.\n\n   \
  \ - Note that the kernel is mapped into every process's address space (with\n  \
  \    the exception of session space which might be different) so using any\n   \
  \   process's DTB from the same session will work to read kernel data\n      structures.\
  \ If this plugin fails, try psscan to find potential DTBs.\n    "
args: {process_name: The name of the process to search for.}
class_name: WinFindDTB
epydoc: rekall.plugins.windows.common.WinFindDTB-class.html
layout: plugin
module: rekall.plugins.windows.common
title: find_dtb
---


### Notes

1. This is an internally used plugin for discovering the Directory Table Base
   (DTB) on windows systems. It is unlikely to be useful to a user by itself.