---
layout: plugin
title: pstree
abstract: |
  Print process list as a tree

epydoc: rekall.plugins.windows.pstree.PSTree-class.html
args:
  verbose: 'Show more details.'
  pid: 'One or more pids of processes to select.'
  eprocess: 'Kernel addresses of eprocess structs.'
  phys_eprocess: 'Physical addresses of eprocess structs.'
  proc_regex: 'A regex to select a process by name.'
  method: 'Method to list processes (Default uses all methods).'

---

This plugin displays all known processes in a tree form (i.e. the process
parents with their children). This is useful to see which process launched
another process.

### Notes

1. Sometimes malware will launch a processes called "lsass.exe" or
   "csrss.exe". This plugin helps to highlight discrepencies since these
   processes are normally only launched from known processes.

2. Using the **verbose=1** flag will also print the command lines of each
   process as determined by three methods:

   * cmd: **task.Peb.ProcessParameters.CommandLine
   * path: **task.Peb.ProcessParameters.ImagePathName
   * audit: **task.SeAuditProcessCreationInfo.ImageFileName.Name**

### Sample output

```
win7.elf 14:55:19> pstree verbose=1
Name                                        Pid   PPid   Thds   Hnds Time
---------------------------------------- ------ ------ ------ ------ ------------------------
 0xFA8002259060:csrss.exe                   348    340      9    436 2012-10-01 21:39:57+0000
    cmd: %SystemRoot%\system32\csrss.exe ObjectDirectory=\Windows SharedSection=1024,20480,768 Windows=On SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserServerDllInitialization,3 ServerDll=winsrv:ConServerDllInitialization,2 ServerDll=sxssrv,4 ProfileControl=Off MaxRequestThreads=16
    path: C:\Windows\system32\csrss.exe
    audit: \Device\HarddiskVolume2\Windows\System32\csrss.exe
 0xFA8000901060:wininit.exe                 384    340      3     75 2012-10-01 21:39:57+0000
    cmd: wininit.exe
    path: C:\Windows\system32\wininit.exe
    audit: \Device\HarddiskVolume2\Windows\System32\wininit.exe
. 0xFA800206D5F0:services.exe               480    384     11    208 2012-10-01 21:39:58+0000
     cmd: C:\Windows\system32\services.exe
     path: C:\Windows\system32\services.exe
     audit: \Device\HarddiskVolume2\Windows\System32\services.exe
.. 0xFA80024F85D0:svchost.exe               236    480     19    455 2012-10-01 14:40:01+0000
      cmd: C:\Windows\system32\svchost.exe -k LocalService
      path: C:\Windows\system32\svchost.exe
      audit: \Device\HarddiskVolume2\Windows\System32\svchost.exe
```