---
layout: plugin
title: yarascan
abstract: |
  Scan using yara signatures.

epydoc: rekall.plugins.linux.yarascan.LinYaraScan-class.html
args:
  string: 'A verbatim string to search for.'
  scan_physical: 'If specified we scan the physcial address space.'
  yara_file: 'The yara signature file to read.'
  yara_expression: 'If provided we scan for this yarra expression.'
  pid: 'One or more pids of processes to select.'
  proc_regex: 'A regex to select a process by name.'
  phys_task: 'Physical addresses of task structs.'
  task: 'Kernel addresses of task structs.'
  task_head: 'Use this as the first task to follow the list.'
  method: 'Method to list processes (Default uses all methods).'
  dtb: 'The DTB physical address.'

---

