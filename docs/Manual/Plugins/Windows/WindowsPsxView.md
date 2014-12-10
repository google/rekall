---
layout: plugin
title: psxview
abstract: |
  Find hidden processes with various process listings

epydoc: rekall.plugins.windows.malware.psxview.WindowsPsxView-class.html
args:
  pid: 'One or more pids of processes to select.'
  eprocess: 'Kernel addresses of eprocess structs.'
  phys_eprocess: 'Physical addresses of eprocess structs.'
  proc_regex: 'A regex to select a process by name.'
  method: 'Method to list processes (Default uses all methods).'
  dtb: 'The DTB physical address.'

---

