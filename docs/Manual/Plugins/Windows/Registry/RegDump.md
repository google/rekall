---
layout: plugin
title: regdump
abstract: |
  Dump all registry hives from memory into a dump directory.

epydoc: rekall.plugins.windows.registry.printkey.RegDump-class.html
args:
  dump_dir: 'Path suitable for dumping files. (Required)'
  hive_offsets: 'A list of hive offsets as found by hivelist. If not provided we call hivescan ourselves and list the keys on all hives.'
  hive_regex: 'A regex to filter hive names.If not provided we use all hives.'

---

