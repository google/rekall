---
abstract: "A Simple plugin which only yarascans the physical Address Space.\n\n  \
  \  This plugin should not trigger profile autodetection and therefore should be\n\
  \    usable on any file at all.\n    "
args: {binary_string: 'A binary string (encoded as hex) to search for. e.g. 000102[1-200]0506
    (type: String)

    ', context: 'Context to print after the hit. (type: IntParser)



    * Default: 64', hits: 'Quit after finding this many hits. (type: IntParser)



    * Default: 10', limit: 'The length of data to search. (type: IntParser)



    * Default: 18446744073709551616', pre_context: 'Context to print before the hit.
    (type: IntParser)



    * Default: 0', start: 'Start searching from this offset. (type: IntParser)



    * Default: 0', string: 'A verbatim string to search for. (type: String)

    ', verbosity: 'An integer reflecting the amount of desired output: 0 = quiet,
    10 = noisy. (type: IntParser)



    * Default: 1', yara_expression: 'If provided we scan for this yara expression.
    (type: String)

    ', yara_file: 'The yara signature file to read. (type: String)

    '}
class_name: SimpleYaraScan
epydoc: rekall.plugins.yarascanner.SimpleYaraScan-class.html
layout: plugin
module: rekall.plugins.yarascanner
title: simple_yarascan
---
