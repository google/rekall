---
layout: plugin
title: pstree
abstract: |
  Print process list as a tree

epydoc: rekall.plugins.windows.pstree.PSTree-class.html
args:
  verbose: 'Show more details.'
  pid: 'One or more pids of processes to select.'
  eprocess: 'Kernel addresses of eprocess structs.'
  phys_eprocess: 'Physical addresses of eprocess structs.'
  proc_regex: 'A regex to select a process by name.'
  method: 'Method to list processes (Default uses all methods).'

---

