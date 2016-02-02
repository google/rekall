---
abstract: Enumerate command consoles.
args: {}
class_name: Consoles
epydoc: rekall.plugins.windows.malware.cmdhistory.Consoles-class.html
layout: plugin
module: rekall.plugins.windows.malware.cmdhistory
title: consoles
---

Similar to [cmdscan](CmdScan.html) the consoles plugin finds commands that
attackers typed into cmd.exe or executed via backdoors. However, instead of
scanning for **COMMAND_HISTORY**, this plugin scans for
**CONSOLE_INFORMATION**. The major advantage to this plugin is it not only
prints the commands attackers typed, but it collects the entire screen buffer
(input and output). For instance, instead of just seeing "dir", you'll see
exactly what the attacker saw, including all files and directories listed by the
"dir" command.

Additionally, this plugin prints the following:

* The original console window title and current console window title
* The name and pid of attached processes (walks a **LIST_ENTRY** to enumerate
  all of them if more than one)
* Any aliases associated with the commands executed. For example, attackers can
  register an alias such that typing "hello" actually executes "cd system"
* The screen coordinates of the cmd.exe console.


### Notes

This plugin is pretty fragile since it relies on reversed structures in
undocumented code. We are working on improving the situation here but there is a
moderate chance that it will produce no results or garbage results.

### Sample Output

```
win7.elf 22:23:10> consoles
**************************************************
ConsoleProcess: conhost.exe Pid: 2652
Console: 0xffd96200 CommandHistorySize: 50
HistoryBufferCount: 4 HistoryBufferMax: 4
OriginalTitle: Console2 command window
Title: Administrator: Console2 command window - vol.exe  --profile Win7SP1x64 --file \\.\pmem
AttachedProcess: vol.exe Pid: 2920 Handle: 0xd8
AttachedProcess: vol.exe Pid: 2912 Handle: 0xd4
AttachedProcess: cmd.exe Pid: 2644 Handle: 0x5c
----
CommandHistory: 0xb4410 Application: vol.exe Flags: Allocated
CommandCount: 0 LastAdded: -1 LastDisplayed: -1
FirstCommand: 0 CommandCountMax: 50
ProcessHandle: 0xd8
----
CommandHistory: 0xb40c0 Application: vol.exe Flags: Allocated
CommandCount: 0 LastAdded: -1 LastDisplayed: -1
FirstCommand: 0 CommandCountMax: 50
ProcessHandle: 0xd4
----
CommandHistory: 0xb3ee0 Application: winpmem_1.1-write.exe Flags:
CommandCount: 0 LastAdded: -1 LastDisplayed: -1
FirstCommand: 0 CommandCountMax: 50
ProcessHandle: 0x0
----
CommandHistory: 0x7ea40 Application: cmd.exe Flags: Allocated, Reset
CommandCount: 3 LastAdded: 2 LastDisplayed: 2
FirstCommand: 0 CommandCountMax: 50
ProcessHandle: 0x5c
Cmd #0 at 0x5ea70: cd \Users\a\Desktop
Cmd #1 at 0x5b920: winpmem_1.1-write.exe -w -l
Cmd #2 at 0xb3e70: vol.exe --profile Win7SP1x64 --file \\.\pmem
----
Screen 0x60ef0 X:117 Y:500
Dump:
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>cd \Users\a\Desktop

C:\Users\a\Desktop>winpmem_1.1-write.exe -w -l
Will enable write mode
Loaded Driver.

C:\Users\a\Desktop>vol.exe --profile Win7SP1x64 --file \\.\pmem
Python 2.7.3 (default, Apr 10 2012, 23:31:26) [MSC v.1500 32 bit (Intel)]
Type "copyright", "credits" or "license" for more information.

IPython 0.12.1 -- An enhanced Interactive Python.
?         -> Introduction and overview of IPython's features.
%quickref -> Quick reference.
help      -> Python's own help system.
object?   -> Details about 'object', use 'object??' for extra details.


The Volatility Memory Forensic Framework technology preview (3.0_tp2).

NOTE: This is pre-release software and is provided for evauation only. Please
check at http://volatility.googlecode.com/ for officially supported versions.

This program is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License.
Win7SP1x64:pmem 07:41:08> pslist
------------------------> pslist()
  Offset (V)   Name                    PID   PPID   Thds     Hnds   Sess  Wow64 Start                Exit

-------------- -------------------- ------ ------ ------ -------- ------ ------ -------------------- ----------------
----
0xfa80008959e0 System                    4      0     85      502 ------  False 2012-10-01 21:39:51  -

0xfa8001994310 smss.exe                272      4      2       29 ------  False 2012-10-01 21:39:51  -
```