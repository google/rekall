---
layout: plugin
title: pedump
abstract: |
  Dump a PE binary from memory.

epydoc: rekall.plugins.windows.procdump.PEDump-class.html
args:
  address_space: ''
  image_base: 'The address of the image base (dos header).'
  out_fd: ''
  out_file: 'The file name to write.'
  pid: 'One or more pids of processes to select.'
  eprocess: 'Kernel addresses of eprocess structs.'
  phys_eprocess: 'Physical addresses of eprocess structs.'
  proc_regex: 'A regex to select a process by name.'
  method: 'Method to list processes (Default uses all methods).'

---

