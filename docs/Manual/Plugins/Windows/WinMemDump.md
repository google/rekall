---
layout: plugin
title: memdump
abstract: |
  Dump the addressable memory for a process

epydoc: rekall.plugins.windows.taskmods.WinMemDump-class.html
args:
  dump_dir: 'Path suitable for dumping files. (Required)'
  coalesce: 'Merge contiguous pages into larger ranges.'
  pid: 'One or more pids of processes to select.'
  eprocess: 'Kernel addresses of eprocess structs.'
  phys_eprocess: 'Physical addresses of eprocess structs.'
  proc_regex: 'A regex to select a process by name.'
  method: 'Method to list processes (Default uses all methods).'

---

