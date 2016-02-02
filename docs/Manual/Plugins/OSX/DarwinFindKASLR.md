---
abstract: "A scanner for KASLR slide values in the Darwin kernel.\n\n    The scanner\
  \ works by looking up a known data structure and comparing\n    its actual location\
  \ to its expected location. Verification is a similar\n    process, using a second\
  \ constant. This takes advantage of the fact that both\n    data structures are\
  \ in a region of kernel memory that maps to the physical\n    memory in a predictable\
  \ way (see ID_MAP_VTOP).\n\n    Human-readable output includes values of the kernel\
  \ version string (which is\n    used for validation) for manual review, in case\
  \ there are false positives.\n    "
args: {}
class_name: DarwinFindKASLR
epydoc: rekall.plugins.darwin.common.DarwinFindKASLR-class.html
layout: plugin
module: rekall.plugins.darwin.common
title: find_kaslr
---
