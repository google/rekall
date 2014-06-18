---
layout: plugin
title: psaux
abstract: |
  Gathers processes along with full command line and start time.

epydoc: rekall.plugins.linux.psaux.PSAux-class.html
args:
  pid: 'One or more pids of processes to select.'
  proc_regex: 'A regex to select a process by name.'
  phys_task: 'Physical addresses of task structs.'
  task: 'Kernel addresses of task structs.'
  task_head: 'Use this as the first task to follow the list.'

---

