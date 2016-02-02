---
abstract: A plugin to list objects.
args: {}
class_name: Lister
epydoc: rekall.plugins.core.Lister-class.html
layout: plugin
module: rekall.plugins.core
title: l
---

Sometimes in the interactive console we receive a generator or a list. Use the
`l` plugin to quickly print each value in the list.

In the below example we instantiate the PsActiveProcessHeadHook and walk the
list of processes (this is one of the `pslist` methods).

```text
[1] win7.elf 23:48:12> head = session.profile.get_constant_object("PsActiveProcessHead", "_LIST_ENTRY")

[1] win7.elf 23:48:32> l head.list_of_type("_EPROCESS", "ActiveProcessLinks")
---------------------> l(head.list_of_type("_EPROCESS", "ActiveProcessLinks"))
[_EPROCESS _EPROCESS] @ 0xFA80008959E0 (pid=4)
  0x00 Pcb                          [_KPROCESS Pcb] @ 0xFA80008959E0
  0x160 ProcessLock                  [_EX_PUSH_LOCK ProcessLock] @ 0xFA8000895B40
  0x168 CreateTime                    [WinFileTime:CreateTime]: 0x506A0DA7 (2012-10-01 21:39:51Z)
  0x170 ExitTime                      [WinFileTime:ExitTime]: 0x00000000 (-)
  0x178 RundownProtect               [_EX_RUNDOWN_REF RundownProtect] @ 0xFA8000895B58
  0x180 UniqueProcessId               [unsigned int:UniqueProcessId]: 0x00000004
  0x188 ActiveProcessLinks           [_LIST_ENTRY ActiveProcessLinks] @ 0xFA8000895B68
  ....
```
