---
abstract: List all the registry hives on the system.
args: {hive-offsets: 'A list of hive offsets as found by hivelist. If not provided
    we call hivelist ourselves and list the keys on all hives. (type: ArrayIntParser)

    ', hive_regex: A regex to filter hive names.If not provided we use all hives.}
class_name: Hives
epydoc: rekall.plugins.windows.registry.registry.Hives-class.html
layout: plugin
module: rekall.plugins.windows.registry.registry
title: hives
---

