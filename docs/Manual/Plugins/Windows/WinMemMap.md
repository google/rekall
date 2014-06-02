---
layout: plugin
title: memmap
abstract: |
  Calculates the memory regions mapped by a process.

epydoc: rekall.plugins.windows.taskmods.WinMemMap-class.html
args:
  coalesce: 'Merge contiguous pages into larger ranges.'
  pid: 'One or more pids of processes to select.'
  eprocess: 'Kernel addresses of eprocess structs.'
  phys_eprocess: 'Physical addresses of eprocess structs.'
  proc_regex: 'A regex to select a process by name.'
  method: 'Method to list processes (Default uses all methods).'

---

