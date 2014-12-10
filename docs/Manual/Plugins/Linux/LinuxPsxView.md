---
layout: plugin
title: psxview
abstract: |
  Find hidden processes comparing various process listings.

epydoc: rekall.plugins.linux.psxview.LinuxPsxView-class.html
args:
  pid: 'One or more pids of processes to select.'
  proc_regex: 'A regex to select a process by name.'
  phys_task: 'Physical addresses of task structs.'
  task: 'Kernel addresses of task structs.'
  task_head: 'Use this as the first task to follow the list.'
  method: 'Method to list processes (Default uses all methods).'
  dtb: 'The DTB physical address.'

---

