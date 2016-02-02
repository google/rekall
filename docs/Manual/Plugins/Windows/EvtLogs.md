---
abstract: Extract Windows Event Logs (XP/2003 only)
args: {hive-offsets: 'A list of hive offsets as found by hivelist. If not provided
    we call hivelist ourselves and list the keys on all hives. (type: ArrayIntParser)

    ', hive_regex: A regex to filter hive names.If not provided we use all hives.,
  verbosity: 'An integer reflecting the amount of desired output: 0 = quiet, 10 =
    noisy. (type: IntParser)



    * Default: 1'}
class_name: EvtLogs
epydoc: rekall.plugins.windows.registry.evtlogs.EvtLogs-class.html
layout: plugin
module: rekall.plugins.windows.registry.evtlogs
title: evtlogs
---


The evtlogs command extracts and parses binary event logs from memory. Binary
event logs are found on Windows XP and 2003 machines, therefore this plugin only
works on these architectures. These files are extracted from VAD of the
services.exe process, parsed and shown as output.

### Notes

1. This plugin will only work on Windows XP/2003. Modern windows systems use
   evtx event log format. We are still working on supporting these logs.

### Sample output

```text
xp-laptop-2005-06-25.img 16:43:19> evtlogs
---------------------------------> evtlogs()
TimeWritten Filename Computer Sid Source Event Id Event Type Message
----------- -------- -------- --- ------ -------- ---------- -------
2004-05-05 19:36:55+0000 SecEvent.Evt MOIT-A-PHXMOD2 S-1-5-18 Security 612 Success '-';'+';'+';'+';'+';'+';'-';'-';'-';'-';'+';'+';'+';'+';'+';'+';'+';'+';'MOIT-A-PHXMOD2$';'BALTIMORE';'(0x0,0x3E7)'
2004-05-05 19:36:56+0000 SecEvent.Evt MOIT-A-PHXMOD2 S-1-5-18 Security 618 Success 'MOIT-A-PHXMOD2$';'BALTIMORE';'(0x0,0x3E7)';'PolEfDat: <binary data> (none);  '
2004-05-05 19:37:03+0000 SecEvent.Evt MOIT-A-PHXMOD2 S-1-5-18 Security 537 Failure 'AJ.Morning';'BALTIMORE';'11';'User32  ';'Negotiate';'MOIT-A-PHXMOD2';'0xC000005E';'0x0'
2004-05-05 19:37:03+0000 SecEvent.Evt MOIT-A-PHXMOD2 S-1-5-21-487349131-2095749132-2248483902-19753 Security 528 Success 'AJ.Morning';'BALTIMORE';'(0x0,0x113AD)';'2';'User32  ';'Negotiate';'MOIT-A-PHXMOD2';'{5c92d34f-85d3-2f5d-d036-759d7c97bfd7}'
2004-05-05 19:37:32+0000 SecEvent.Evt MOIT-A-PHXMOD2 S-1-5-19 Security 528 Success 'LOCAL SERVICE';'NT AUTHORITY';'(0x0,0x3E5)';'5';'Advapi  ';'Negotiate';'';'{00000000-0000-0000-0000-000000000000}'
2004-05-05 19:37:33+0000 SecEvent.Evt MOIT-A-PHXMOD2 S-1-5-21-487349131-2095749132-2248483902-19753 Security 596 Failure '619be804-cde6-484f-aff4-2a5e588d6eef';'';'';'0x57'
```
