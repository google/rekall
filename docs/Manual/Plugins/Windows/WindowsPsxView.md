---
abstract: Find hidden processes with various process listings
args: {eprocess: 'Kernel addresses of eprocess structs. (type: ArrayIntParser)

    ', method: "Method to list processes. (type: ChoiceArray)\n\n\n* Valid Choices:\n\
    \    - PsActiveProcessHead\n    - CSRSS\n    - PspCidTable\n    - Sessions\n \
    \   - Handles\n    - PSScan\n    - Thrdproc\n\n\n* Default: PsActiveProcessHead,\
    \ CSRSS, PspCidTable, Sessions, Handles, PSScan, Thrdproc", phys_eprocess: 'Physical
    addresses of eprocess structs. (type: ArrayIntParser)

    ', pid: 'One or more pids of processes to select. (type: ArrayIntParser)

    ', proc_regex: 'A regex to select a process by name. (type: RegEx)

    '}
class_name: WindowsPsxView
epydoc: rekall.plugins.windows.malware.psxview.WindowsPsxView-class.html
layout: plugin
module: rekall.plugins.windows.malware.psxview
title: psxview
---

