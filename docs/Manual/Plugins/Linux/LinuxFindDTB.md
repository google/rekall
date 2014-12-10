
---
layout: plugin
title: find_dtb
abstract: |
    A scanner for DTB values.

    For linux, the dtb values are taken directly from the symbol file. Linux has
    a direct mapping between the kernel virtual address space and the physical
    memory.  This is the difference between the virtual and physical addresses
    (aka PAGE_OFFSET). This is defined by the __va macro:

    ```
    #define __va(x) ((void *)((unsigned long) (x) + PAGE_OFFSET))
    ```

    This one plugin handles both 32 and 64 bits.
    

epydoc: rekall.plugins.linux.common.LinuxFindDTB-class.html
---
