---
layout: plugin
title: devicetree
abstract: |
  Show device tree.

epydoc: rekall.plugins.windows.malware.devicetree.DeviceTree-class.html
args:
  address_space: ''
  scan_in_kernel: 'Scan in the kernel address space'

---


Windows uses a layered driver architecture, or driver chain so that multiple
drivers can inspect or respond to an IRP. Rootkits often insert drivers (or
devices) into this chain for filtering purposes (to hide files, hide network
connections, steal keystrokes or mouse movements). The devicetree plugin shows
the relationship of a driver object to its devices (by walking
_DRIVER_OBJECT.DeviceObject.NextDevice) and any attached devices
(_DRIVER_OBJECT.DeviceObject.AttachedDevice).


### Notes

In the current implementation this plugin uses scanning methods to locate the
driver and device objects. This is an inefficient method which is also
susceptible to false positives and active subversion. We are working on
converting this plugin to use the [object_tree](ObjectTree.html) plugin to
directly parse kernel driver structures.

### Sample output

```
[snip]
DRV 0x2bb31060 \Driver\winpmem
---| DEV 0xfa80019ba060 pmem FILE_DEVICE_UNKNOWN
DRV 0x2bb36600 \Driver\TermDD
---| DEV 0xfa80019ff040 - FILE_DEVICE_8042_PORT
------| ATT 0xfa80019ff980 - - \Driver\mouclass FILE_DEVICE_MOUSE
---| DEV 0xfa80019e2040 - FILE_DEVICE_8042_PORT
------| ATT 0xfa80019e2960 - - \Driver\kbdclass FILE_DEVICE_KEYBOARD
[snip]
```

In the above we can see that the winpmem driver has a device called "pmem". We
also can see the mouse and keyboard drivers attached to the terminal services
driver.
