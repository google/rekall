---
layout: plugin
title: threads
abstract: |
  Enumerate threads.

epydoc: rekall.plugins.windows.taskmods.Threads-class.html
args:
  verbosity: 'Add more output.'
  pid: 'One or more pids of processes to select.'
  eprocess: 'Kernel addresses of eprocess structs.'
  phys_eprocess: 'Physical addresses of eprocess structs.'
  proc_regex: 'A regex to select a process by name.'
  method: 'Method to list processes (Default uses all methods).'

---

