
---
layout: plugin
title: dtbscan2
abstract: |
    A Fast scanner for hidden DTBs.

    This scanner uses the fact that the virtual address of the DTB is always the
    same. We walk over all the physical pages, assume each page is a DTB and try
    to resolve the constant to a physical address.
    

epydoc: rekall.plugins.windows.pfn.DTBScan2-class.html
---
