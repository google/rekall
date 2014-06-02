---
layout: plugin
title: users
abstract: |
  Enumerate all users of this system.
  
  Ref:
  samparse.pl from RegRipper.
  
  copyright 2012 Quantum Analytics Research, LLC
  Author: H. Carvey, keydet89@yahoo.com

epydoc: rekall.plugins.windows.registry.printkey.Users-class.html
args:
  hive_offsets: 'A list of hive offsets as found by hivelist. If not provided we call hivescan ourselves and list the keys on all hives.'
  hive_regex: 'A regex to filter hive names.If not provided we use all hives.'

---

