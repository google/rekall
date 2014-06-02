---
layout: plugin
title: pas2vas
abstract: |
  Resolves a physical address to a virtual addrress in a process.

epydoc: rekall.plugins.windows.pas2kas.WinPas2Vas-class.html
args:
  offsets: 'A list of physical offsets to resolve.'
  pid: 'One or more pids of processes to select.'
  eprocess: 'Kernel addresses of eprocess structs.'
  phys_eprocess: 'Physical addresses of eprocess structs.'
  proc_regex: 'A regex to select a process by name.'
  method: 'Method to list processes (Default uses all methods).'

---

