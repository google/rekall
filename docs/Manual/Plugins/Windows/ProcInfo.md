---
layout: plugin
title: procinfo
abstract: |
  Dump detailed information about a running process.

epydoc: rekall.plugins.windows.procinfo.ProcInfo-class.html
args:
  pid: 'One or more pids of processes to select.'
  eprocess: 'Kernel addresses of eprocess structs.'
  phys_eprocess: 'Physical addresses of eprocess structs.'
  proc_regex: 'A regex to select a process by name.'
  method: 'Method to list processes (Default uses all methods).'

---

The **procinfo** plugin displays basic information about a process. It takes all
the usual process selectors (e.g. pid, name etc) and prints information about
the PE file (using **peinfo**) as well as the process environment strings.