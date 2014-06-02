---
layout: plugin
title: maps
abstract: |
  Gathers process maps for linux.

epydoc: rekall.plugins.linux.proc_maps.ProcMaps-class.html
args:
  pid: 'One or more pids of processes to select.'
  proc_regex: 'A regex to select a process by name.'
  phys_task: 'Physical addresses of task structs.'
  task: 'Kernel addresses of task structs.'
  task_head: 'Use this as the first task to follow the list.'

---

