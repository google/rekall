/*++
    Kernel Land Physical Memory Dumper
    Copyright (C) June 2008  Matthieu Suiche http://www.msuiche.net

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

Module Name:

    - win32d.h

Abstract:

    - This driver aims to provide a full dump of the physical memory (RAM).
    - Because since Windows 2003 SP1, access to \\PhysicalMemory has been disabled from user-land,
    - and there are no public kernel dumper. I decide to release mine as an open source project.

Environment:

    - Kernel mode

Revision History:

    - Matthieu Suiche

--*/

#ifndef _WIN32DD_H_
#define _WIN32DD_H_

#include "mm.h"

//
// IOCTL
//
#define IOCTL_WRITE_RAW_DUMP CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)
#define IOCTL_WRITE_CRSH_DUMP CTL_CODE(FILE_DEVICE_UNKNOWN, 0x2, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

/* This is used to query the driver about memory stats.

   In - Encode the level and method in bits 8-16.
   Out - struct Win32MemroyInfo.
 */
#define IOCTL_GET_INFO CTL_CODE(FILE_DEVICE_UNKNOWN, 0x100, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

#pragma pack(2)
struct Win32MemroyInfo {
  LARGE_INTEGER CR3;
  LARGE_INTEGER KPCR;
  ULONG NumberOfRuns;

  // A Null terminated array of ranges.
  PHYSICAL_MEMORY_RANGE Run[1];
};

#define STATUS_DONE 'ENOD'
#define STATUS_FAIL 'LIAF'
#define STATUS_PEND 'DNEP'


/* These should be changed for incident response purposes to prevent trivial
 * rootkit subversion.
 */
#define SILENT_OPERATION 0
#define WIN32DD_DEVICE_NAME L"win32dd"
#define WIN32DD_VERSION "v2.0RC1"

/* When we are silent we do not emit any debug messages. */
#if SILENT_OPERATION
#define DbgPrint(fmt, ...)
#endif


enum WDD_ACQUISITION_MODE {
  ACQUISITION_MODE_PHYSICAL_MEMORY = 0,
  ACQUISITION_MODE_IO_MEMORY = 1
};

/*
  Our Device Extension Structure.
*/
typedef struct _DEVICE_EXTENSION {
  /* How we should acquire memory. */
  enum WDD_ACQUISITION_MODE mode;

  /* If we read from \\Device\\PhysicalMemory, this is the handle to that. */
  HANDLE MemoryHandle;
  PPHYSICAL_MEMORY_DESCRIPTOR descriptor;
} DEVICE_EXTENSION, *PDEVICE_EXTENSION;


#endif
