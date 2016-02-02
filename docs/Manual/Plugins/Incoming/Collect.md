---
abstract: "Collect instances of struct of type 'type_name'.\n\n    This plugin will\
  \ find all other plugins that produce 'type_name' and merge\n    all their output.\
  \ For example, running collect 'proc' will give you a\n    rudimentary psxview.\n\
  \n    This plugin is mostly used by other plugins, like netstat and psxview.\n\n\
  \    "
args: {type_name: The type (struct) to collect.}
class_name: Collect
epydoc: rekall.plugins.common.search.Collect-class.html
layout: plugin
module: rekall.plugins.common.search
title: collect
---
