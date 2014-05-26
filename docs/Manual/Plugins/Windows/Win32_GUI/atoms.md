---
layout: plugin
category: Win32k GUI
title: atoms
abstract: |
  Print session and window station atom tables.

  An atom table is a system-defined table that stores strings and corresponding
  identifiers [(MSDN)]. An application places a string in an atom table and
  receives a 16-bit integer, called an atom, that can be used to access the
  string. A string that has been placed in an atom table is called an atom name.

  The global atom table is available to all applications. When an application
  places a string in the global atom table, the system generates an atom that is
  unique throughout the system. Any application that has the atom can obtain the
  string it identifies by querying the global atom table.

  (The global atom tables are only global within each session).

  [(MSDN)]: http://msdn.microsoft.com/en-us/library/windows/desktop/ms649053.aspx

epydoc:
  rekall.plugins.windows.taskmods.WinPsList-class.html
---

Using this plugin you can find registered window messages, rogue injected DLL
paths, window class names, etc.

Sample output:

```
  Offset(P)    Session    WindowStation           Atom      RefCount   HIndex     Pinned     Name
-------------- ---------- ------------------ -------------- ---------- ---------- ---------- ----
0xf8a002871020 0          WinSta0                    0xc001 1          1          True       StdExit
0xf8a002871020 0          WinSta0                    0xc002 1          2          True       StdNewDocument
0xf8a002871020 0          WinSta0                    0xc003 1          3          True       StdOpenDocument
0xf8a002871020 0          WinSta0                    0xc004 1          4          True       StdEditDocument
0xf8a002871020 0          WinSta0                    0xc005 1          5          True       StdNewfromTemplate
0xf8a002871020 0          WinSta0                    0xc006 1          6          True       StdCloseDocument
0xf8a002871020 0          WinSta0                    0xc007 1          7          True       StdShowItem
0xf8a002871020 0          WinSta0                    0xc008 1          8          True       StdDoVerbItem
0xf8a002871020 0          WinSta0                    0xc009 1          9          True       System
0xf8a002871020 0          WinSta0                    0xc00a 1          10         True       OLEsystem
0xf8a002871020 0          WinSta0                    0xc00b 1          11         True       StdDocumentName
0xf8a002871020 0          WinSta0                    0xc00c 1          12         True       Protocols
0xf8a002871020 0          WinSta0                    0xc00d 1          13         True       Topics
0xf8a002871020 0          WinSta0                    0xc00e 1          14         True       Formats
0xf8a002871020 0          WinSta0                    0xc00f 1          15         True       Status
0xf8a002871020 0          WinSta0                    0xc010 1          16         True       EditEnvItems
0xf8a002811020 0          ------------------         0xc045 2          69         False      MSUIM.Msg.LBUpdate
0xf8a002811020 0          ------------------         0xc046 2          70         False      MSUIM.Msg.MuiMgrDirtyUpdate
0xf8a002811020 0          ------------------         0xc047 1          71         False      C:\Windows\system32\wls0wndh.dll
0xf8a002811020 0          ------------------         0xc048 27         72         False      {FB8F0821-0164-101B-84ED-08002B2EC713}
0xf8a002811020 0          ------------------         0xc049 2          73         False      MMDEVAPI
```
