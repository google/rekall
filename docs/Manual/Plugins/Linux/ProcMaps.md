---
layout: plugin
title: maps
abstract: |
  Gathers process maps for linux by walking the `task.mm.mmap` list.

epydoc: rekall.plugins.linux.proc_maps.ProcMaps-class.html
args:
  pid: 'One or more pids of processes to select.'
  proc_regex: 'A regex to select a process by name.'
  phys_task: 'Physical addresses of task structs.'
  task: 'Kernel addresses of task structs.'
  task_head: 'Use this as the first task to follow the list.'

---

### Sample output

```
[1] Windows7_VMware(Win7x64+Ubuntu686,Ubuntu64)_VBox(XPSP3x86).ram 17:18:41> maps
---------------------------------------------------------------------------> maps()
  Pid        Start           End       Flags      Pgoff      Major  Minor      Inode                                        File Path
-------- -------------- -------------- ------ -------------- ------ ------ ------------- --------------------------------------------------------------------------------
966      0x000000000000 0x000000000000 ---    0x000000000000 0      0      0                                                                                             
1031     0x000000400000 0x00000043a000 r-x    0x000000000000 -      -      -             -                                                                               
1031     0x000000639000 0x00000063a000 r--    0x000000039000 -      -      -             -                                                                               
1031     0x00000063a000 0x00000063b000 rw-    0x00000003a000 -      -      -             -                                                                               
1031     0x0000012be000 0x0000012df000 rw-    0x000000000000 0      0      0             [heap]                                                                          
1031     0x000000000000 0x000000000000 ---    0x000000000000 0      0      0                                                                                             
1042     0x000000000000 0x000000000000 ---    0x000000000000 0      0      0                                                                                             
1056     0x000000400000 0x000000407000 r-x    0x000000000000 -      -      0             /sbin/getty                                                                     
1056     0x000000606000 0x000000607000 r--    0x000000006000 -      -      0             /sbin/getty                                                                     
1056     0x000000607000 0x000000608000 rw-    0x000000007000 -      -      0             /sbin/getty                                                                     
1056     0x000000608000 0x00000060a000 rw-    0x000000000000 0      0      0                                                                                             
1056     0x000000000000 0x000000000000 ---    0x000000000000 0      0      0                                                                                             
1058     0x000000400000 0x000000407000 r-x    0x000000000000 -      -      0             /sbin/getty                                                                     
1058     0x000000606000 0x000000607000 r--    0x000000006000 -      -      0             /sbin/getty                                                                     
1058     0x000000607000 0x000000608000 rw-    0x000000007000 -      -      0             /sbin/getty                                                                     
1058     0x000000608000 0x00000060a000 rw-    0x000000000000 0      0      0                                                                                             
1058     0x00000194c000 0x00000196d000 rw-    0x000000000000 0      0      0             [heap]                                                                          
1058     0x7f44e0f56000 0x7f44e1493000 r--    0x000000000000 252    0      660935        /usr/lib/locale/locale-archive                                                  
1058     0x000000000000 0x000000000000 ---    0x000000000000 0      0      0                                                                                             
1074     0x7f8f09279000 0x7f8f09285000 r-x    0x000000000000 -      -      0             /lib/x86_64-linux-gnu/libnss_files-2.17.so                                      
1074     0x7f8f09285000 0x7f8f09484000 ---    0x00000000c000 -      -      0             /lib/x86_64-linux-gnu/libnss_files-2.17.so                                      
1074     0x7f8f09484000 0x7f8f09485000 r--    0x00000000b000 -      -      0             /lib/x86_64-linux-gnu/libnss_files-2.17.so                                      
1074     0x7f8f09485000 0x7f8f09486000 rw-    0x00000000c000 -      -      0             /lib/x86_64-linux-gnu/libnss_files-2.17.so                                      
1074     0x7f8f09486000 0x7f8f09491000 r-x    0x000000000000 -      -      -             -                                                                               
1074     0x7f8f09491000 0x7f8f09690000 ---    0x00000000b000 -      -      -             -                                                                               
1074     0x7f8f09690000 0x7f8f09691000 r--    0x00000000a000 -      -      -             -                                                                               
1074     0x7f8f09691000 0x7f8f09692000 rw-    0x00000000b000 -      -      -             -                                                                               
[...]
```
