---
layout: plugin
title: find_dtb
abstract: |
  A plugin to search for the Directory Table Base for windows systems.

  There are a number of ways to find the DTB:

  - Scanner method: Scans the image for a known kernel process, and read the
    DTB from its Process Environment Block (PEB).

  - Get the DTB from the KPCR structure.

  - Note that the kernel is mapped into every process's address space (with
    the exception of session space which might be different) so using any
    process's DTB from the same session will work to read kernel data
    structures. If this plugin fails, try psscan to find potential DTBs.

epydoc: rekall.plugins.windows.common.WinFindDTB-class.html
args:
  process_name: 'The name of the process to search for.'

---


### Notes

1. This is an internally used plugin for discovering the Directory Table Base
   (DTB) on windows systems. It is unlikely to be useful to a user by itself.