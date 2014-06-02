---
layout: plugin
title: vad
abstract: |
  Concise dump of the VAD.
  
  Similar to windbg's !vad.

epydoc: rekall.plugins.windows.vadinfo.VAD-class.html
args:
  pid: 'One or more pids of processes to select.'
  eprocess: 'Kernel addresses of eprocess structs.'
  phys_eprocess: 'Physical addresses of eprocess structs.'
  proc_regex: 'A regex to select a process by name.'
  method: 'Method to list processes (Default uses all methods).'

---

