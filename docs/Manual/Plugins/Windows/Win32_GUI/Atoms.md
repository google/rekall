---
abstract: "Print session and window station atom tables.\n\n    From:\n    http://msdn.microsoft.com/en-us/library/windows/desktop/ms649053.aspx\n\
  \n    An atom table is a system-defined table that stores strings and\n    corresponding\
  \ identifiers. An application places a string in an atom table\n    and receives\
  \ a 16-bit integer, called an atom, that can be used to access\n    the string.\
  \ A string that has been placed in an atom table is called an atom\n    name.\n\n\
  \    The global atom table is available to all applications. When an application\n\
  \    places a string in the global atom table, the system generates an atom that\n\
  \    is unique throughout the system. Any application that has the atom can\n  \
  \  obtain the string it identifies by querying the global atom table.\n\n    (The\
  \ global atom tables are only global within each session).\n    "
args: {verbosity: 'An integer reflecting the amount of desired output: 0 = quiet,
    10 = noisy. (type: IntParser)



    * Default: 1', win32k_profile: Force this profile to be used for Win32k.}
class_name: Atoms
epydoc: rekall.plugins.windows.gui.atoms.Atoms-class.html
layout: plugin
module: rekall.plugins.windows.gui.atoms
title: atoms
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
