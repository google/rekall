---
abstract: Yara scan process memory using the ReadProcessMemory() API.
args: {binary_string: 'A binary string (encoded as hex) to search for. e.g. 000102[1-200]0506
    (type: String)

    ', context: 'Context to print after the hit. (type: IntParser)



    * Default: 64', hits: 'Quit after finding this many hits. (type: IntParser)



    * Default: 10', pids: 'One or more pids of processes to select. (type: ArrayIntParser)



    * Default: ', pre_context: 'Context to print before the hit. (type: IntParser)



    * Default: 0', proc_regex: 'A regex to select a process by name. (type: RegEx)

    ', string: 'A verbatim string to search for. (type: String)

    ', verbosity: 'An integer reflecting the amount of desired output: 0 = quiet,
    10 = noisy. (type: IntParser)



    * Default: 1', yara_expression: 'If provided we scan for this yara expression.
    (type: String)

    ', yara_file: 'The yara signature file to read. (type: String)

    '}
class_name: ProcessYaraScanner
epydoc: rekall.plugins.response.processes.ProcessYaraScanner-class.html
layout: plugin
module: rekall.plugins.response.processes
title: yarascan
---
