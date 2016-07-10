---
abstract: Dump all registry hives from memory into a dump directory.
args: {dump_dir: 'Path suitable for dumping files. (type: String)

    ', hive-offsets: 'A list of hive offsets as found by hivelist. If not provided
    we call hivelist ourselves and list the keys on all hives. (type: ArrayIntParser)

    ', hive_regex: A regex to filter hive names.If not provided we use all hives.}
class_name: RegDump
epydoc: rekall.plugins.windows.registry.printkey.RegDump-class.html
layout: plugin
module: rekall.plugins.windows.registry.printkey
title: regdump
---

