---
abstract: "Scan the physical memory attempting to find hypervisors.\n\n    Once EPT\
  \ values are found, you can use them to inspect virtual machines\n    with any of\
  \ the rekall modules by using the --ept parameter and\n    specifying the guest\
  \ virtual machine profile.\n\n    Supports the detection of the following virtualization\
  \ techonlogies:\n      * Intel VT-X with EPT. Microarchitectures:\n        + Westmere\n\
  \        + Nehalem\n        + Sandybridge\n        + Ivy Bridge\n        + Haswell\n\
  \n      * Intel VT-X without EPT (unsupported page translation in rekall).\n   \
  \     + Penryn\n\n    For the specific processor models that support EPT, please\
  \ check:\n    http://ark.intel.com/products/virtualizationtechnology.\n    "
args: {image_is_guest: 'The image is for a guest VM, not the host. (type: Boolean)



    * Default: False', no_nested: 'Don''t do nested VM detection. (type: Boolean)



    * Default: False', no_validation: '[DEBUG SETTING] Disable validation of VMs.
    (type: Boolean)



    * Default: False', offset: 'Offset in the physical image to start the scan. (type:
    IntParser)



    * Default: 0', quick: 'Perform quick VM detection. (type: Boolean)



    * Default: False', show_all: 'Also show VMs that failed validation. (type: Boolean)



    * Default: False', verbosity: 'An integer reflecting the amount of desired output:
    0 = quiet, 10 = noisy. (type: IntParser)



    * Default: 1'}
class_name: VmScan
epydoc: rekall.plugins.hypervisors.VmScan-class.html
layout: plugin
module: rekall.plugins.hypervisors
title: vmscan
---
