---
abstract: "Tries to find the DTB address for the Darwin/XNU kernel.\n\n    As the\
  \ XNU kernel developed over the years, the best way of deriving this\n    information\
  \ changed. This class now offers multiple methods of finding the\n    DTB. Calling\
  \ find_dtb should automatically select the best method for the\n    job, based on\
  \ the profile. It will also attempt to fall back on less ideal\n    ways of getting\
  \ the DTB if the best way fails.\n    "
args: {vm_kernel_slide: 'OS X 10.8 and later: kernel ASLR slide. (type: IntParser)

    '}
class_name: DarwinFindDTB
epydoc: rekall.plugins.darwin.common.DarwinFindDTB-class.html
layout: plugin
module: rekall.plugins.darwin.common
title: find_dtb
---
