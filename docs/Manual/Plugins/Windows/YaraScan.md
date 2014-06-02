---
layout: plugin
title: yarascan
abstract: |
  Scan using yara signatures.

epydoc: rekall.plugins.windows.malware.yarascan.YaraScan-class.html
args:
  string: 'A verbatim string to search for.'
  scan_vads: 'If specified we scan the vads of processes, else we scan their entire address spaces. Note that scanning the entire address space will typically also include the kernel, while targetting VADs only will only include the addresses mapped by the process.'
  scan_physical: 'If specified we scan the physcial address space.'
  yara_file: 'The yara signature file to read.'
  yara_expression: 'If provided we scan for this yarra expression.'
  pid: 'One or more pids of processes to select.'
  eprocess: 'Kernel addresses of eprocess structs.'
  phys_eprocess: 'Physical addresses of eprocess structs.'
  proc_regex: 'A regex to select a process by name.'
  method: 'Method to list processes (Default uses all methods).'

---

