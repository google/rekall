---
abstract: Displays all object Types on the system.
args: {}
class_name: Objects
epydoc: rekall.plugins.windows.misc.Objects-class.html
layout: plugin
module: rekall.plugins.windows.misc
title: object_types
---

The windows kernel has the notion of a **Kernel Object**. Objects are managed by
the kernel through a dedicated API. Kernel Objects are typically used to manage
resources which the kernel manages on behalf of user space, for example, open
files are managed via the **_FILE_OBJECT** object.

There is a fixed number of kernel objects, each is described by an
**_OBJECT_TYPE** structure, the address of which can be found at the
**ObpObjectTypes** symbol.

### Notes

1. Each time a new object is created by the kernel, the **Number of Objects**
   count increases. For every free's object, this number decreases. The counter
   therefore represents the total number of active instances of this object
   type.

2. The number of kernel objects varies between windows kernel version. In order
   to find the size of the **ObpObjectTypes** array, Rekall uses the reference
   count on the **Type** object type - each kernel object type has a unique
   **_OBJECT_TYPE** structure.

3. The **Number of Objects** count also has forensic significance. For example
   the total number of **Process** objects represents the total number of
   _EPROCESS structures in current use (Note that a process may be terminated
   but the _EPROCESS is still kept in use).


### Sample output

The below output indicates that there should be 41 processes active, and 548 threads.

```
win7.elf 01:39:36> object_types
-----------------> object_types()
Index  Number Objects PoolType        Name
----- --------------- --------------- ----
    2              42 NonPagedPool    Type
    3              40 PagedPool       Directory
    4             173 PagedPool       SymbolicLink
    5             704 PagedPool       Token
    6               3 NonPagedPool    Job
    7              41 NonPagedPool    Process
    8             548 NonPagedPool    Thread
    9               0 NonPagedPool    UserApcReserve
   10               1 NonPagedPool    IoCompletionReserve
...
```