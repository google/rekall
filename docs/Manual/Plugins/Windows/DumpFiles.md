---
layout: plugin
title: dumpfiles
abstract: |
  Dump files from memory.
  
      The interface is loosely based on the Volatility plugin of the same name,
      although the implementation is quite different.

epydoc: rekall.plugins.windows.cache.DumpFiles-class.html
args:
  pid: 'One or more pids of processes to select.'
  eprocess: 'Kernel addresses of eprocess structs.'
  phys_eprocess: 'Physical addresses of eprocess structs.'
  proc_regex: 'A regex to select a process by name.'
  method: 'Method to list processes (Default uses all methods).'
  dtb: 'The DTB physical address.'

---

