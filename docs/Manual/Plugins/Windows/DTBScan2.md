---
abstract: "A Fast scanner for hidden DTBs.\n\n    This scanner uses the fact that\
  \ the virtual address of the DTB is always the\n    same. We walk over all the physical\
  \ pages, assume each page is a DTB and try\n    to resolve the constant to a physical\
  \ address.\n\n    This plugin was written based on ideas and discussion with thomasdullien.\n\
  \    "
args: {}
class_name: DTBScan2
epydoc: rekall.plugins.windows.pfn.DTBScan2-class.html
layout: plugin
module: rekall.plugins.windows.pfn
title: dtbscan2
---



