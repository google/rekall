---
abstract: Checks if any processes are sharing credential structures
args: {method: "Method to list processes (Default uses all methods). (type: ChoiceArray)\n\
    \n\n* Valid Choices:\n    - InitTask\n\n\n* Default: InitTask", phys_task: 'Physical
    addresses of task structs. (type: ArrayIntParser)

    ', pid: 'One or more pids of processes to select. (type: ArrayIntParser)

    ', proc_regex: A regex to select a process by name., task: 'Kernel addresses of
    task structs. (type: ArrayIntParser)

    ', task_head: 'Use this as the first task to follow the list. (type: IntParser)

    '}
class_name: CheckCreds
epydoc: rekall.plugins.linux.check_creds.CheckCreds-class.html
layout: plugin
module: rekall.plugins.linux.check_creds
title: check_creds
---

In order for rootkits to elevate the privileges of a given process, they need
to alter the current effective identifier of a process. Before kernel 2.6, this
was done by setting a couple of integers in the process task to the desired ID.

After 2.6, credentials are handled internally via the `task_struct->cred`
member. Likely due to laziness or a poor attempt at remaining stealth, some
rootkits simply reuse the `cred` member of tasks that have the desired
credentials (most often ID 0: `root`).

This plugin reports the location of the `cred` member of each task. When this
structure is being reused, you'll see more than one line of output with the
same `cred` address.

### Sample output

```
Windows7_VMware(Win7x64+Ubuntu686,Ubuntu64)_VBox(XPSP3x86).ram 15:40:12> check_creds
-----------------------------------------------------------------------> check_creds()
     Cred      PID      Command             
-------------- -------- --------------------
0x88003b86c900 966      dbus-daemon         
0x88003c766480 1031     systemd-logind      
0x88003c1a7380 1056     getty               
0x88003c1d2180 1103     irqbalance          
0x88003c1d23c0 1290     kauditd             
0x88003c1a6c00 1058     getty               
0x880036b2e840 1132     atd                 
0x88003b96d080 1055     getty               
0x88003c767440 1335     bash                
0x88003c1a6cc0 1074     sshd                
0x88003c1d2c00 1131     cron                
0x88003cbc0900 1160     login               
0x88003c183140 1081     acpid               
0x88003b9ded80 1042     getty               
0x88003b9dee40 1049     getty               
0x88003c1a78c0 1176     whoopsie            
0x88003c69a480 1486     dnsmasq             
0x88003cbc1440 1199     libvirtd            
```
