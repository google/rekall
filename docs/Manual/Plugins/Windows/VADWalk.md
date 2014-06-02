---
layout: plugin
title: vadwalk
abstract: |
  Walk the VAD tree

epydoc: rekall.plugins.windows.vadinfo.VADWalk-class.html
args:
  pid: 'One or more pids of processes to select.'
  eprocess: 'Kernel addresses of eprocess structs.'
  phys_eprocess: 'Physical addresses of eprocess structs.'
  proc_regex: 'A regex to select a process by name.'
  method: 'Method to list processes (Default uses all methods).'

---

