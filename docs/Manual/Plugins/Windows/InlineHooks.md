---
layout: plugin
title: hooks_inline
abstract: |
  Detect API hooks in process and kernel memory

epydoc: rekall.plugins.windows.malware.apihooks.InlineHooks-class.html
args:
  pid: 'One or more pids of processes to select.'
  eprocess: 'Kernel addresses of eprocess structs.'
  phys_eprocess: 'Physical addresses of eprocess structs.'
  proc_regex: 'A regex to select a process by name.'
  method: 'Method to list processes (Default uses all methods).'
  dtb: 'The DTB physical address.'

---

