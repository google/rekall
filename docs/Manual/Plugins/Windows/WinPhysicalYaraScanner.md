---
abstract: "An experimental yara scanner over the physical address space.\n\n    Yara\
  \ does not provide a streaming interface, which means that when we scan\n    for\
  \ yara rules we can only ever match strings within the same buffer. This\n    is\
  \ a problem for physical address space scanning because each page (although\n  \
  \  it might appear to be contiguous) usually comes from a different\n    process/mapped\
  \ file.\n\n    Therefore we need a more intelligent way to apply yara signatures\
  \ on the\n    physical address space:\n\n    1. The original set of yara rules is\
  \ converted into a single rule with all\n    the strings from all the rules in it.\
  \ The rule has a condition \"any of them\"\n    which will match any string appearing\
  \ in the scanned buffer.\n\n    2. This rule is then applied over the physical address\
  \ space.\n\n    3. For each hit we derive a context and add the hit to the context.\n\
  \n    4. Finally we test all the rules within the same context with the original\n\
  \    rule set.\n    "
args: {context: 'Context to print after the hit. (type: IntParser)



    * Default: 64', hits: 'Quit after finding this many hits. (type: IntParser)



    * Default: 10', limit: 'The length of data to search. (type: IntParser)



    * Default: 18446744073709551616', pre_context: 'Context to print before the hit.
    (type: IntParser)



    * Default: 0', start: 'Start searching from this offset. (type: IntParser)



    * Default: 0', verbosity: 'An integer reflecting the amount of desired output:
    0 = quiet, 10 = noisy. (type: IntParser)



    * Default: 1', yara_ast: 'If provided we scan for this yara expression specified
    in the yara JSON AST. (type: String)

    ', yara_expression: 'If provided we scan for this yara expression specified in
    the yara DSL. (type: String)

    '}
class_name: WinPhysicalYaraScanner
epydoc: rekall.plugins.windows.malware.yarascan.WinPhysicalYaraScanner-class.html
layout: plugin
module: rekall.plugins.windows.malware.yarascan
title: yarascan_physical
---
