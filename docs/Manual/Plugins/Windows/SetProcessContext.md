---
layout: plugin
title: cc
abstract: |
    Set the current process context.

epydoc: rekall.plugins.windows.misc.SetProcessContext-class.html
---


One of Rekall's most powerfull features is the ability for the tool to resolve a
memory address back to a module or a symbol name which is known to exist at that
address. In order to perform this resolution, Rekall needs to be aware of the
virtual address layout (i.e. which dll or kernel module is mapped into which
region of the virtual address space).

However, the virtual address space has a different layout, for each process,
since processes have a unique page table. Therefore the same address in the
virtual address space may be resolved to different physical pages.

In order to correctly resolve the virtual address to a mapped dll, Rekall needs
to load the correct `process context`. Each process context:

* Has a unique address space - this is the address space of the process.

* Has a unique vad - Rekall uses the vad to find out which dlls are mapped into
  which regions in the process's address space.

* Each mapped PE executable has a unique export table. Rekall uses the export
  table to help resolve symbols when a profile is not found.

This plugin can be used programmatically as a context manager:

```
cc = session.plugins.cc()
with cc:
   cc.SetProcessContext(eprocess)

   print session.address_resolver.format_address(address)
```

The context manager ensures that the previous process context is restored.

### Notes

1. This plugin is used heavily within Rekall.  2. Process contexts are generally
   cached. This means that the first time an address resolution is required in a
   particular context, it might take slightly longer. Subsequent name
   resolutions should be quick as the context is cached.

### Sample output

This plugin has no visible effects, except that after running it, the session's
default address space is changed.

```
win7_trial_64bit.dmp.E01 00:08:34> cc 3060
DEBUG:root:Switching to process context: conhost.exe (Pid 3060@0xfa8000bbd060)
Switching to process context: conhost.exe (Pid 3060@0xfa8000bbd060)
win7_trial_64bit.dmp.E01 00:08:36> session.GetParameter("process_context")
                           Out<30> [_EPROCESS _EPROCESS] @ 0xFA8000BBD060 (pid=3060)
win7_trial_64bit.dmp.E01 00:08:38> session.GetParameter("default_address_space")
                           Out<31> <AMD64PagedMemory @ 0x678321 Process 3060>
```
