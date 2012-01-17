/**
   This file implement methods for reading through the win32 device.

Revision History:
  Michael Cohen (scudette@gmail.com)

*/

#ifndef __READ_H
#define __READ_H

/* Read a page through the PhysicalMemory device. */
LONG PhysicalMemoryPartialRead(IN PDEVICE_EXTENSION extension,
                               LARGE_INTEGER offset, PCHAR buf, ULONG count);

/* Read a large buffer by concatenating lots of small reads. */
NTSTATUS DeviceRead(IN PDEVICE_EXTENSION extension, LARGE_INTEGER offset,
                    PCHAR buf, ULONG *count,
                    LONG (*handler)(IN PDEVICE_EXTENSION,
                                    LARGE_INTEGER, PCHAR, ULONG)
                    );


/* Actual read handler. */
NTSTATUS win32Read(IN PDEVICE_OBJECT  DeviceObject, IN PIRP  Irp);

#endif
