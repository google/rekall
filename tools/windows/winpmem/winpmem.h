/*
   Copyright 2012 Michael Cohen <scudette@gmal.com>

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

#ifndef _WINPMEM_H_
#define _WINPMEM_H_

#include <ntifs.h>
#include <wdmsec.h>
#include <initguid.h>
#include <stdarg.h>
#include <stdio.h>

#define MI_CONVERT_PHYSICAL_TO_PFN(Pa) (Pa >> 12)

//
// IOCTL
//
// This is used to query the driver about memory stats.
#define IOCTL_GET_INFO CTL_CODE(FILE_DEVICE_UNKNOWN, 0x100, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

#define IOCTL_SET_MODE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x101, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

// This is the structure which is returned.
#pragma pack(push, 2)

struct PmemMemroyInfo {
  LARGE_INTEGER CR3;
  LARGE_INTEGER KPCR;
  ULONG NumberOfRuns;

  // A Null terminated array of ranges.
  PHYSICAL_MEMORY_RANGE Run[1];
};


enum PMEM_ACQUISITION_MODE {
  ACQUISITION_MODE_MAP_IO_SPACE = 0,
  ACQUISITION_MODE_PHYSICAL_MEMORY = 1
};

struct PmemMemoryControl {
  enum PMEM_ACQUISITION_MODE mode;
};


/* These should be changed for incident response purposes to prevent trivial
 * rootkit subversion.
 */
#define SILENT_OPERATION 0
#define PMEM_DEVICE_NAME L"pmem"
#define PMEM_VERSION "v1.0"

/* When we are silent we do not emit any debug messages. */
#if SILENT_OPERATION == 1
#define WinDbgPrint(fmt, ...)
#else
#define WinDbgPrint DbgPrint
#endif


/*
  Our Device Extension Structure.
*/
typedef struct _DEVICE_EXTENSION {
  /* How we should acquire memory. */
  enum WDD_ACQUISITION_MODE mode;

  /* If we read from \\Device\\PhysicalMemory, this is the handle to that. */
  HANDLE MemoryHandle;
} DEVICE_EXTENSION, *PDEVICE_EXTENSION;

// 5e1ce668-47cb-410e-a664-5c705ae4d71b
DEFINE_GUID(GUID_DEVCLASS_PMEM_DUMPER,
            0x5e1ce668L,
            0x47cb,
            0x410e,
            0xa6, 0x64, 0x5c, 0x70, 0x5a, 0xe4, 0xd7, 0x1b);

#pragma pack(pop)

#endif

