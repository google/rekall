---
abstract: "A mixin for those plugins requiring a physical address space.\n\n     \
  \   Args:\n          physical_address_space: The physical address space to use.\
  \ If not\n            specified we use the following options:\n\n            1)\
  \ session.physical_address_space,\n\n            2) Guess using the load_as() plugin,\n\
  \n            3) Use session.kernel_address_space.base.\n\n        "
args: {verbosity: 'An integer reflecting the amount of desired output: 0 = quiet,
    10 = noisy. (type: IntParser)



    * Default: 1'}
class_name: Hostname
epydoc: rekall.plugins.linux.common.Hostname-class.html
layout: plugin
module: rekall.plugins.linux.common
title: hostname
---

