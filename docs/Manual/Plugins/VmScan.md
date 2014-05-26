
---
layout: plugin
title: vmscan
abstract: |
    Scan the physical memory attempting to find hypervisors.

    Once EPT values are found, you can use them to inspect virtual machines
    with any of the rekall modules by using the --ept parameter and
    specifying the guest virtual machine profile.

    Supports the detection of the following virtualization techonlogies:
      * Intel VT-X with EPT. Microarchitectures:
        + Westmere
        + Nehalem
        + Sandybridge
        + Ivy Bridge
        + Haswell

      * Intel VT-X without EPT (unsupported page translation in rekall).
        + Penryn

    For the specific processor models that support EPT, please check:
    http://ark.intel.com/products/virtualizationtechnology.
    

epydoc: rekall.plugins.hypervisors.VmScan-class.html
---
