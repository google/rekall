---
layout: plugin
title: vtop
abstract: |
  Prints information about the virtual to physical translation.

epydoc: rekall.plugins.windows.pfn.VtoP-class.html
args:
  virtual_address: 'Specify to see all the fops, even if they are known.'
  address_space: 'The address space to use.'

---

This plugin displays all the page translation steps needed to resolve a virtual
address to a physical address.

### Notes

1. The plugin uses the current default address space to calculate the
   mapping. If you want to resolve the virtual address in a process space you
   will need to switch the process context first (i.e. use the
   [cc](SetProcessContext.html) plugin.

### Sample output

```
win7_trial_64bit.dmp.E01 23:52:53> vtop 0xfa8000a2d060
Virtual 0xfa8000a2d060 Page Directory 0x00187000
pml4e@ 0x187fa8 = 0x3c00863
pdpte@ 0x3c00000 = 0x3c01863
pde@ 0x3c01028 = 0x30c009e3
Large page mapped 0x30e2d060
Physical Address 0x30c2d060
```