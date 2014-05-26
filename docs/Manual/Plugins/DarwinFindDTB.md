
---
layout: plugin
title: find_dtb
abstract: |
    Tries to find the DTB address for the Darwin/XNU kernel.

    As the XNU kernel developed over the years, the best way of deriving this
    information changed. This class now offers multiple methods of finding the
    DTB. Calling find_dtb should automatically select the best method for the
    job, based on the profile. It will also attempt to fall back on less ideal
    ways of getting the DTB if the best way fails.
    

epydoc: rekall.plugins.darwin.common.DarwinFindDTB-class.html
---
