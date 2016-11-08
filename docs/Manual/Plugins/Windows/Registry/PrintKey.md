---
abstract: Print a registry key, and its subkeys and values
args: {hive-offsets: 'A list of hive offsets as found by hivelist. If not provided
    we call hivelist ourselves and list the keys on all hives. (type: ArrayIntParser)

    ', hive_regex: A regex to filter hive names.If not provided we use all hives.,
  key: 'Registry key to print.


    * Default: ', recursive: 'If set print the entire subtree. (type: Boolean)



    * Default: False', verbosity: 'An integer reflecting the amount of desired output:
    0 = quiet, 10 = noisy. (type: IntParser)



    * Default: 1'}
class_name: PrintKey
epydoc: rekall.plugins.windows.registry.printkey.PrintKey-class.html
layout: plugin
module: rekall.plugins.windows.registry.printkey
title: printkey
---

