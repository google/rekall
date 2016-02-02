---
abstract: "Visualize the kernel object tree.\n\n    Ref:\n    http://msdn.microsoft.com/en-us/library/windows/hardware/ff557762(v=vs.85).aspx\n\
  \    "
args: {type_regex: 'Filter the type of objects shown.


    * Default: .'}
class_name: ObjectTree
epydoc: rekall.plugins.windows.misc.ObjectTree-class.html
layout: plugin
module: rekall.plugins.windows.misc
title: object_tree
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

In the next example we search for SymbolicLinks for the pmem device and discover
when the pmem driver was loaded.

```
win7.elf 01:38:53> object_tree type_regex="Symbolic"
0xf8a0003a58a0 SymbolicLink         . Root#MS_PPPOEMINIPORT#0000#{cac88484-7515-4c03-82e6-71a87abac361}-> \Device\00000034 (2012-10-01 21:39:55+0000)
0xf8a0003c1030 SymbolicLink         . Root#*ISATAP#0000#{ad498944-762f-11d0-8dcb-00c04fc3358c}-> \Device\00000001 (2012-10-01 21:39:51+0000)
0xf8a00007fda0 SymbolicLink         . WMIAdminDevice-> \Device\WMIAdminDevice (2012-10-01 21:39:45+0000)
0xf8a0056e8dd0 SymbolicLink         . pmem-> \Device\pmem (2012-10-01 14:40:44+0000)
0xf8a0001111c0 SymbolicLink         . Root#MS_NDISWANIP#0000#{cac88484-7515-4c03-82e6-71a87abac361}-> \Device\00000032 (2012-10-01 21:39:55+0000)
0xf8a0003bef20 SymbolicLink         . Root#MS_NDISWANBH#0000#{cac88484-7515-4c03-82e6-71a87abac361}-> \Device\00000031 (2012-10-01 21:39:55+0000)
0xf8a000006f40 SymbolicLink         . Global-> \GLOBAL?? (2012-10-01 21:39:45+0000)
```