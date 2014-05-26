
---
layout: plugin
title: find_kaslr
abstract: |
    A scanner for KASLR slide values in the Darwin kernel.

    The scanner works by looking up a known data structure and comparing
    its actual location to its expected location. Verification is a similar
    process, using a second constant. This takes advantage of the fact that both
    data structures are in a region of kernel memory that maps to the physical
    memory in a predictable way (see ID_MAP_VTOP).

    Human-readable output includes values of the kernel version string (which is
    used for validation) for manual review, in case there are false positives.
    

epydoc: rekall.plugins.darwin.common.DarwinFindKASLR-class.html
---
