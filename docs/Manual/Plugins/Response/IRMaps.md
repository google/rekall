---
abstract: Examine the process memory maps.
args: {offset: 'Only print the vad corresponding to this offset. (type: SymbolAddress)

    ', pids: 'One or more pids of processes to select. (type: ArrayIntParser)



    * Default: ', proc_regex: 'A regex to select a process by name. (type: RegEx)

    ', regex: 'A regular expression to filter VAD filenames. (type: RegEx)

    ', verbosity: 'With high verbosity print more information on each region. (type:
    IntParser)



    * Default: 1'}
class_name: IRMaps
epydoc: rekall.plugins.response.linux.IRMaps-class.html
layout: plugin
module: rekall.plugins.response.linux
title: maps
---
