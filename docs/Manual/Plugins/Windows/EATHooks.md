---
layout: plugin
title: hooks_eat
abstract: |
  Detect EAT hooks in process and kernel memory

epydoc: rekall.plugins.windows.malware.apihooks.EATHooks-class.html
args:
  pid: 'One or more pids of processes to select.'
  eprocess: 'Kernel addresses of eprocess structs.'
  phys_eprocess: 'Physical addresses of eprocess structs.'
  proc_regex: 'A regex to select a process by name.'
  method: 'Method to list processes (Default uses all methods).'
  dtb: 'The DTB physical address.'

---

