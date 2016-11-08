---
abstract: "Enumerate all users of this system.\n\n    Ref:\n    samparse.pl from RegRipper.\n\
  \n    # copyright 2012 Quantum Analytics Research, LLC\n    # Author: H. Carvey,\
  \ keydet89@yahoo.com\n    "
args: {hive-offsets: 'A list of hive offsets as found by hivelist. If not provided
    we call hivelist ourselves and list the keys on all hives. (type: ArrayIntParser)

    ', hive_regex: A regex to filter hive names.If not provided we use all hives.,
  verbosity: 'An integer reflecting the amount of desired output: 0 = quiet, 10 =
    noisy. (type: IntParser)



    * Default: 1'}
class_name: Users
epydoc: rekall.plugins.windows.registry.printkey.Users-class.html
layout: plugin
module: rekall.plugins.windows.registry.printkey
title: users
---

