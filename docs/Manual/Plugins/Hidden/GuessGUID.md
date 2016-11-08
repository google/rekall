---
abstract: Try to guess the exact version of a kernel module by using an index.
args: {minimal_match: 'The minimal number of comparison points to be considered. Sometimes
    not all comparison points can be used since they may not be mapped. (type: IntParser)



    * Default: 1', module: 'The name of the module to guess. (type: String)

    ', verbosity: 'An integer reflecting the amount of desired output: 0 = quiet,
    10 = noisy. (type: IntParser)



    * Default: 1'}
class_name: GuessGUID
epydoc: rekall.plugins.windows.index.GuessGUID-class.html
layout: plugin
module: rekall.plugins.windows.index
title: guess_guid
---
