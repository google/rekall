---
abstract: An experimental yara scanner over the physical address space.
args: {context: 'Context to print after the hit. (type: IntParser)



    * Default: 64', hits: 'Quit after finding this many hits. (type: IntParser)



    * Default: 10', limit: 'The length of data to search. (type: IntParser)



    * Default: 18446744073709551616', pre_context: 'Context to print before the hit.
    (type: IntParser)



    * Default: 0', start: 'Start searching from this offset. (type: IntParser)



    * Default: 0', yara_expression: 'If provided we scan for this yara expression.
    (type: String)

    '}
class_name: WinPhysicalYaraScanner
epydoc: rekall.plugins.windows.malware.yarascan.WinPhysicalYaraScanner-class.html
layout: plugin
module: rekall.plugins.windows.malware.yarascan
title: yarascan_physical
---
