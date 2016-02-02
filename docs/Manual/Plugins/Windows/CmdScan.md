---
abstract: Extract command history by scanning for _COMMAND_HISTORY
args: {max_history: 'Value of history buffer size. See HKEY_CURRENT_USER\Console\HistoryBufferSize
    for default.


    * Default: 50'}
class_name: CmdScan
epydoc: rekall.plugins.windows.malware.cmdhistory.CmdScan-class.html
layout: plugin
module: rekall.plugins.windows.malware.cmdhistory
title: cmdscan
---

The cmdscan plugin searches the memory of csrss.exe on XP/2003/Vista/2008 and
conhost.exe on Windows 7 for commands that attackers entered through a console
shell (cmd.exe). This is one of the most powerful commands you can use to gain
visibility into an attackers actions on a victim system, whether they opened
cmd.exe through an RDP session or proxied input/output to a command shell from a
networked backdoor.

This plugin finds structures known as **COMMAND_HISTORY** by looking for a known
constant value (**MaxHistory**) and then applying sanity checks. It is important
to note that the **MaxHistory** value can be changed by right clicking in the
top left of a cmd.exe window and going to Properties. The value can also be
changed for all consoles opened by a given user by modifying the registry key
HKCU\Console\HistoryBufferSize. The default is 50 on Windows systems, meaning
the most recent 50 commands are saved. You can tweak it if needed by using the
--max_history=NUMBER parameter.

The structures used by this plugin are not public (i.e. Microsoft does not
produce PDBs for them), thus they're not available in WinDBG or any other
forensic framework. They were reverse engineered by Michael Ligh from the
conhost.exe and winsrv.dll binaries.

In addition to the commands entered into a shell, this plugin shows:

* The name of the console host process (csrss.exe or conhost.exe)

* The name of the application using the console (whatever process is using cmd.exe)

* The location of the command history buffers, including the current buffer count, last added command, and last displayed command

* The application process handle

Due to the scanning technique this plugin uses, it has the capability to find
commands from both active and closed consoles.


### Notes

This plugin is pretty fragile since it relies on reversed structures in
undocumented code. We are working on improving the situation here but there is a
moderate chance that it will produce no results or garbage results.

### Sample Output

The following showing an operator using the winpmem acquisition tool to analyse
the live memory of a Windows 7 machine.

```
win7.elf 22:15:39> cmdscan
-----------------> cmdscan()
**************************************************
CommandProcess: conhost.exe Pid: 2652
CommandHistory: 0x7ea40 Application: cmd.exe Flags: Allocated, Reset
CommandCount: 3 LastAdded: 2 LastDisplayed: 2
FirstCommand: 0 CommandCountMax: 50
ProcessHandle: 0x5c
Cmd    Address     Text
--- -------------- --------------------------------------------------
  0 0x00000005ea70 cd \Users\a\Desktop
  1 0x00000005b920 winpmem_1.1-write.exe -w -l
  2 0x0000000b3e70 vol.exe --profile Win7SP1x64 --file \\.\pmem
 15 0x000000040158
 16 0x00000007d3b0

**************************************************
CommandProcess: conhost.exe Pid: 2652
CommandHistory: 0xb40c0 Application: vol.exe Flags: Allocated
CommandCount: 0 LastAdded: -1 LastDisplayed: -1
FirstCommand: 0 CommandCountMax: 50
ProcessHandle: 0xd4
Cmd    Address     Text
--- -------------- --------------------------------------------------
  0 0x0000001f77e0
  3 0x000000060ef0
  5 0x0000001f77e0
  8 0x000000060ef0
 10 0x0000001f77e0
 13 0x0000ffd96238
 14 0x00000007ec20
 15 0x0000001f7720
 23 0x0000000610a0
 24 0x0000000974e0
**************************************************
CommandProcess: conhost.exe Pid: 2652
CommandHistory: 0xb4410 Application: vol.exe Flags: Allocated
CommandCount: 0 LastAdded: -1 LastDisplayed: -1
FirstCommand: 0 CommandCountMax: 50
ProcessHandle: 0xd8
Cmd    Address     Text
--- -------------- --------------------------------------------------
```