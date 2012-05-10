/**
   This file implement methods for reading through the pmem device.

Revision History:
  Michael Cohen (scudette@gmail.com)

*/

#ifndef __READ_H
#define __READ_H

#include "winpmem.h"

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
NTSTATUS PmemRead(IN PDEVICE_OBJECT  DeviceObject, IN PIRP  Irp);

#endif
