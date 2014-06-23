---
layout: plugin
title: tokens
abstract: |
  Print the SIDs owning each process token.

epydoc: rekall.plugins.windows.registry.getsids.GetSIDs-class.html
args:
  pid: 'One or more pids of processes to select.'
  eprocess: 'Kernel addresses of eprocess structs.'
  phys_eprocess: 'Physical addresses of eprocess structs.'
  proc_regex: 'A regex to select a process by name.'
  method: 'Method to list processes (Default uses all methods).'

---

In windows a process runs with a set of *Tokens*. These tokens are used to
enforce Windows Mandatory ACL system. From a forensic point of view it is
interesting to see what tokens a process is running with.

For non system processes, the process will also possess the token of the user
who started it.

### Sample output

In the below we can see that this cmd.exe process was started by the user `test`
with SID `S-1-5-21-1077689984-2177008626-1601812314-1001`.

```
win8.1.raw 22:41:01> tokens
-------------------> tokens()
Process          Pid   Sid                                                Comment
---------------- ----- -------------------------------------------------- -------
...
cmd.exe          888   S-1-5-21-1077689984-2177008626-1601812314-1001     User: test
cmd.exe          888   S-1-5-21-1077689984-2177008626-1601812314-513      Domain Users
cmd.exe          888   S-1-1-0                                            Everyone
cmd.exe          888   S-1-5-114
cmd.exe          888   S-1-5-21-1077689984-2177008626-1601812314-1002
cmd.exe          888   S-1-5-32-544                                       Administrators
cmd.exe          888   S-1-5-32-545                                       Users
cmd.exe          888   S-1-5-4                                            Interactive
cmd.exe          888   S-1-2-1                                            Console Logon (Users who are logged onto the physical console)
cmd.exe          888   S-1-5-11                                           Authenticated Users
cmd.exe          888   S-1-5-15                                           This Organization
cmd.exe          888   S-1-5-113
cmd.exe          888   S-1-5-5-0-126935                                   Logon Session
cmd.exe          888   S-1-2-0                                            Local (Users with the ability to log in locally)
cmd.exe          888   S-1-5-64-10                                        NTLM Authentication
cmd.exe          888   S-1-16-12288                                       High Mandatory Level
...
```
