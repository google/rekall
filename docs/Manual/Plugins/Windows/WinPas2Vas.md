---
layout: plugin
title: pas2vas
abstract: |
  Resolves a physical address to a virtual addrress in a process.

epydoc: rekall.plugins.windows.pas2kas.WinPas2Vas-class.html
args:
  offsets: 'A list of physical offsets to resolve.'
  pid: 'One or more pids of processes to select.'
  eprocess: 'Kernel addresses of eprocess structs.'
  phys_eprocess: 'Physical addresses of eprocess structs.'
  proc_regex: 'A regex to select a process by name.'
  method: 'Method to list processes (Default uses all methods).'

---

In virtual (or protected) mode, the CPU can not access physical memory
directly. Instead each memory access made by the CPU is translated using the MMU
into a relevant physical address. This translation is controlled by page tables
loaded in the memory address controlled by the CR3 register.

Each processes has a unique page table structure, and therefore a unique view of
physical memory. In order to know what physical address is mapped to each
virtual address you can use the **vtop** plugin. However, the reverse mapping is
not so simple - there can be many virtual addresses mapped to the same physical
address.

This plugin enumerates all virtual to physical mappings in one or more
processes. It then builds a large lookup table in memory to be able to reverse
the mapping. i.e. given a physical address, the plugin is able to determine the
virtual address that maps to it, and in which processes it exists.

Forensically this can be used if you find an interesting string in the physical
image (e.g. with a hex editor) and want to know which process has that physical
memory mapped. Another use case is to detect shared memory between multiple
processes.

### Notes

1. This plugin only enumerates the userspace portion of the process address
   space (since all processes share the same kernel address space).

2. The plugin may take a while to run while it builds its lookup table. The next
   time you run it it should be very fast. The lookup map is also stored in the
   session cache so you can use the **-s** parameter to store the session for
   next time.


### Sample output

In the following we see that the process `vol.exe` is a Wow64 process and maps
**\Windows\SysWOW64\ws2_32.dll**. We want to know who else is using this dll. We
first find the physical address of the mapped dll (note we need to switch to the
correct process context first), then we use the **pas2vas** plugin to determine
which other process has that physical page mapped.

```
win7.elf 12:29:35> pslist
  Offset (V)   Name                    PID   PPID   Thds     Hnds   Sess  Wow64 Start                    Exit
-------------- -------------------- ------ ------ ------ -------- ------ ------ ------------------------ ------------------------
...
0xfa8002193060 vol.exe                2912   2644      1       19      1   True 2012-10-01 14:41:03+0000 -
0xfa80017f9060 vol.exe                2920   2912      4      169      1   True 2012-10-01 14:41:03+0000 -
win7.elf 12:29:59> vad 2912
-----------------> vad(2912)
**************************************************
Pid: 2912 vol.exe
     VAD       lev     start           end        com -       -      Protect              Filename
-------------- --- -------------- -------------- ---- ------- ------ -------------------- --------
0xfa80026f9d80 1         0x74400        0x7443e    3 Mapped  Exe    EXECUTE_WRITECOPY    \Windows\System32\wow64.dll
...
0xfa80021da200 3         0x766c0        0x766f4    2 Mapped  Exe    EXECUTE_WRITECOPY    \Windows\SysWOW64\ws2_32.dll
0xfa80026eb5e0 4         0x75ef0        0x75fdf    2 Mapped  Exe    EXECUTE_WRITECOPY    \Windows\SysWOW64\rpcrt4.dll
...
0xfa80028f59d0 5         0x7fff0     0x7fffffef   -1 Private        READONLY
win7.elf 12:30:08> cc 2912
Switching to process context: vol.exe (Pid 2912@0xfa8002193060)

win7.elf 12:32:45> vtop 0x766c0000
-----------------> vtop(0x766c0000)
Virtual 0x766c0000 Page Directory 0x271ec000
pml4e@ 0x271ec000 = 0x70000008844867
pdpte@ 0x8844008 = 0x80000007845867
pde@ 0x7845d98 = 0x7b55847
pte@ 0x7b55600 = 0x1a58f005
PTE mapped@ 0x7b55600 = 0x1a58f000
Physical Address 0x1a58f000
win7.elf 12:32:53> pas2vas 0x1a58f000

   Physical       Virtual        Pid Name
-------------- -------------- ------ ----
0x00001a58f000 0x0000766c0000   2616 Console.exe
0x00001a58f000 0x0000766c0000   2920 vol.exe
0x00001a58f000 0x0000766c0000   2912 vol.exe
```

We see that `Console.exe` also maps the same dll - probably since it is also a
Wow64 process which requires network access.