---
layout: plugin
title: vaddump
abstract: |
  Dumps out the vad sections to a file

epydoc: rekall.plugins.windows.vadinfo.VADDump-class.html
args:
  dump_dir: 'Path suitable for dumping files. (Required)'
  pid: 'One or more pids of processes to select.'
  eprocess: 'Kernel addresses of eprocess structs.'
  phys_eprocess: 'Physical addresses of eprocess structs.'
  proc_regex: 'A regex to select a process by name.'
  method: 'Method to list processes (Default uses all methods).'

---

