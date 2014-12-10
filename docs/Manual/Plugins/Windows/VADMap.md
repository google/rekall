---
layout: plugin
title: vadmap
abstract: |
  Show physical addresses for all VAD pages.

epydoc: rekall.plugins.windows.vadinfo.VADMap-class.html
args:
  pid: 'One or more pids of processes to select.'
  eprocess: 'Kernel addresses of eprocess structs.'
  phys_eprocess: 'Physical addresses of eprocess structs.'
  proc_regex: 'A regex to select a process by name.'
  method: 'Method to list processes (Default uses all methods).'
  dtb: 'The DTB physical address.'

---

