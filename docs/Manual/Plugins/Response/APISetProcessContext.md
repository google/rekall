---
abstract: A cc plugin for setting process context to live mode.
args: {pids: 'One or more pids of processes to select. (type: ArrayIntParser)



    * Default: ', proc_regex: 'A regex to select a process by name. (type: RegEx)

    ', verbosity: 'An integer reflecting the amount of desired output: 0 = quiet,
    10 = noisy. (type: IntParser)



    * Default: 1'}
class_name: APISetProcessContext
epydoc: rekall.plugins.response.processes.APISetProcessContext-class.html
layout: plugin
module: rekall.plugins.response.processes
title: cc
---
