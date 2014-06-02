---
layout: plugin
title: ptov
abstract: |
  Converts a physical address to a virtual address.

epydoc: rekall.plugins.windows.pfn.PtoV-class.html
args:
  physical_address: ''
  pid: 'One or more pids of processes to select.'
  eprocess: 'Kernel addresses of eprocess structs.'
  phys_eprocess: 'Physical addresses of eprocess structs.'
  proc_regex: 'A regex to select a process by name.'
  method: 'Method to list processes (Default uses all methods).'

---

