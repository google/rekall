---
abstract: Print userassist registry keys and information
args: {hive-offsets: 'A list of hive offsets as found by hivelist. If not provided
    we call hivelist ourselves and list the keys on all hives. (type: ArrayIntParser)

    ', hive_regex: A regex to filter hive names.If not provided we use all hives.,
  verbosity: 'An integer reflecting the amount of desired output: 0 = quiet, 10 =
    noisy. (type: IntParser)



    * Default: 1'}
class_name: UserAssist
epydoc: rekall.plugins.windows.registry.userassist.UserAssist-class.html
layout: plugin
module: rekall.plugins.windows.registry.userassist
title: userassist
---

