---
abstract: Extract command history by scanning for _CONSOLE_INFORMATION
args: {history-buffers: 'Number of history buffere. See HKCU\Console\NumberOfHistoryBuffers.
    Uses 4 by default.


    * Default: 4', max_history: 'Value of history buffer size. See HKEY_CURRENT_USER\Console\HistoryBufferSize
    for default.


    * Default: 50'}
class_name: ConsoleScan
epydoc: rekall.plugins.windows.malware.cmdhistory.ConsoleScan-class.html
layout: plugin
module: rekall.plugins.windows.malware.cmdhistory
title: consolescan
---
