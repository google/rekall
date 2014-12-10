
---
layout: plugin
title: check_syscall
abstract: |
    Checks if the system call table has been altered.

epydoc: rekall.plugins.linux.check_syscall.CheckSyscall-class.html
---

`check_syscall` checks if every syscall handler points to a known symbol in the
profile. All the default syscall handlers for a given kernel should be exported
along with the profile and if this handler is changed, Rekall will detect it.

### Notes

1. Unknown symbols are reported as `Unknown`.
2. Only the handler pointers are checked. If the original handler is still
being used but it has been patched in memory, no hook detection will be done.


### Sample output

```
```
