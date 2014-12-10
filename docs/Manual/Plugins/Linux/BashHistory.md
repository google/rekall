
---
layout: plugin
title: bash
abstract: |
    Scan the bash process for history.

    Based on original algorithm by Andrew Case.
    

epydoc: rekall.plugins.linux.bash.BashHistory-class.html
---

The Bourne Again Shell maintains a history a history of all commands that
have been executed in the current session in memory. `bash` is a plugin that
provides a chronologically ordered list of commands executed by each bash
process, grouped by pid.


### Notes

* Only commands executed in each bash session are stored in memory. So if
you're looking for commands for exitted bash sessions you may be more lucky
by looking at the disk .bash_history file if logging wasn't disabled.

### Sample output

```
Windows7_VMware(Win7x64+Ubuntu686,Ubuntu64)_VBox(XPSP3x86).ram 12:27:35> bash
-----------------------------------------------------------------------> bash()
   Pid Name                 Timestamp                Command
------ -------------------- ------------------------ --------------------
  1335 bash                 2014-03-04 17:16:31+0000 uname -a
```
