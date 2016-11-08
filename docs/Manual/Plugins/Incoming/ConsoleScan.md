---
abstract: Extract command history by scanning for _CONSOLE_INFORMATION
args: {history_buffers: 'Value of history buffer size. See HKEY_CURRENT_USER\Console\HistoryBufferSize
    for default. (type: IntParser)



    * Default: 4', max_history: 'Value of history buffer size. See HKEY_CURRENT_USER\Console\HistoryBufferSize
    for default. (type: IntParser)



    * Default: 50', verbosity: 'An integer reflecting the amount of desired output:
    0 = quiet, 10 = noisy. (type: IntParser)



    * Default: 1'}
class_name: ConsoleScan
epydoc: rekall.plugins.windows.malware.cmdhistory.ConsoleScan-class.html
layout: plugin
module: rekall.plugins.windows.malware.cmdhistory
title: consolescan
---
