---
abstract: Yara scanner which operates on files.
args: {binary_string: 'A binary string (encoded as hex) to search for. e.g. 000102[1-200]0506
    (type: String)

    ', context: 'Context to print after the hit. (type: IntParser)



    * Default: 64', hits: 'Quit after finding this many hits. (type: IntParser)



    * Default: 10', paths: 'Paths to scan. (type: Array)

    ', pre_context: 'Context to print before the hit. (type: IntParser)



    * Default: 0', string: 'A verbatim string to search for. (type: String)

    ', yara_expression: 'If provided we scan for this yara expression. (type: String)

    ', yara_file: 'The yara signature file to read. (type: String)

    '}
class_name: FileYaraScanner
epydoc: rekall.plugins.response.yara.FileYaraScanner-class.html
layout: plugin
module: rekall.plugins.response.yara
title: file_yara
---
