---
abstract: Checks a pe file mapped into memory for hooks.
args: {image_base: 'The base address of the pe image in memory. (type: SymbolAddress)



    * Default: 0', thorough: 'By default we take some optimization. This flags forces
    thorough but slower checks. (type: Boolean)



    * Default: False', type: "Type of hook to display. (type: Choice)\n\n\n* Valid\
    \ Choices:\n    - all\n    - iat\n    - inline\n    - eat\n\n\n* Default: all",
  verbosity: 'An integer reflecting the amount of desired output: 0 = quiet, 10 =
    noisy. (type: IntParser)



    * Default: 1'}
class_name: CheckPEHooks
epydoc: rekall.plugins.windows.malware.apihooks.CheckPEHooks-class.html
layout: plugin
module: rekall.plugins.windows.malware.apihooks
title: check_pehooks
---

