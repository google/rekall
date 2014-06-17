---
layout: plugin
title: object_tree
abstract: |
  Visualize the kernel object tree.

  Ref:
  http://msdn.microsoft.com/en-us/library/windows/hardware/ff557762(v=vs.85).aspx

epydoc: rekall.plugins.windows.misc.ObjectTree-class.html
args:

---

The windows kernel has the notion of a **Kernel Object**. Objects are managed by
the kernel through a dedicated API. Kernel Objects are typically used to manage
resources which the kernel manages on behalf of user space, for example, open
files are managed via the **_FILE_OBJECT** object.

Objects can be named using a directory structure not unlike a
filesystem. Objects are placed inside an **_OBJECT_DIRECTORY** object which
contains other objects, including other directories. This means that named
kernel objects forma tree in memory.

It is possible to discover all currently in-use named objects by following this
object tree in memory, which is what this plugin does. This is an alternative to
the scanning approach employed by plugins like **psscan**, **driverscan** etc.

### Notes

1. The object tree only tracks named objects. So for example Process objects are
   typically not tracked here, but Mutants, SymbolicLinks etc are.

2. It is possible to filter objects by types. So for example to enumerate all
   Mutants one would use the **type_regex="Mutant"** option.

3. *SymbolicLinks* also contain the timestamp when they were created. Note that
   SymbolicLinks are typically used to provide userspace access to a kernel
   driver (via the *CreateFile* api), so a timestamp here is a good indication
   of when a driver was loaded.

### Sample output

```
# Enumeate all drivers
win7.elf 01:25:12> object_tree type_regex="Driver"
-----------------> object_tree(type_regex="Driver")
_OBJECT_HEADER Type                 Name
-------------- -------------------- --------------------
0xfa80025e5d10 Driver               . mrxsmb10
0xfa80025e1190 Driver               . mrxsmb
0xfa8001953940 Driver               . mrxsmb20
....

# We can examine a specific object using the virtual offset.

win7.elf 01:28:18> x=profile._OBJECT_HEADER(0xfa80019fb8d0)
win7.elf 01:28:34> print x.get_object_type()
Driver

# We can dereference the exact object contained in this header (in this case
#  _DRIVER_OBJECT.

win7.elf 01:28:40> print x.Object
[_DRIVER_OBJECT _DRIVER_OBJECT] @ 0xFA80019FB900
  0x00 Type              [short:Type]: 0x00000004
  0x02 Size              [short:Size]: 0x00000150
  0x08 DeviceObject     <_DEVICE_OBJECT Pointer to [0xFA80019FB550] (DeviceObject)>
  0x10 Flags             [unsigned long:Flags]: 0x00000012
  0x18 DriverStart      <Void Pointer to [0xF88003B45000] (DriverStart)>
  0x20 DriverSize        [unsigned long:DriverSize]: 0x0000B000
  0x28 DriverSection    <Void Pointer to [0xFA80019FB7C0] (DriverSection)>
  0x30 DriverExtension  <_DRIVER_EXTENSION Pointer to [0xFA80019FBA50] (DriverExtension)>
  0x38 DriverName       [_UNICODE_STRING DriverName] @ 0xFA80019FB938 (\Driver\rdpbus)
  0x48 HardwareDatabase <_UNICODE_STRING Pointer to [0xF80002B59558] (HardwareDatabase)>
  0x50 FastIoDispatch   <_FAST_IO_DISPATCH Pointer to [0x00000000] (FastIoDispatch)>
  0x58 DriverInit       <Function Pointer to [0xF88003B4D1B0] (DriverInit)>
  0x60 DriverStartIo    <Function Pointer to [0x00000000] (DriverStartIo)>
  0x68 DriverUnload     <Function Pointer to [0xF88003B4B480] (DriverUnload)>
  0x70 MajorFunction    <IndexedArray 28 x Pointer @ 0xFA80019FB970>
win7.elf 01:29:01> print x.Object.DriverName
\Driver\rdpbus
```

