
---
layout: plugin
title: memdump
abstract: |
    Dump the addressable memory for a process.

    This plugin traverses the page tables and dumps all accessible memory for
    the task. Note that this excludes kernel memory even though it is mapped
    into the task.
    

epydoc: rekall.plugins.linux.pslist.LinMemDump-class.html
---
