---
layout: plugin
title: printkey
abstract: |
  Print a registry key, and its subkeys and values

epydoc: rekall.plugins.windows.registry.printkey.PrintKey-class.html
args:
  key: 'Registry key to print.'
  recursive: 'If set print the entire subtree.'
  hive_offsets: 'A list of hive offsets as found by hivelist. If not provided we call hivescan ourselves and list the keys on all hives.'
  hive_regex: 'A regex to filter hive names.If not provided we use all hives.'

---

