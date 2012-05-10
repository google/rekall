#ifndef _WINPMEM_H_
#define _WINPMEM_H_

#include <ntifs.h>
#include <wdmsec.h>
#include <initguid.h>
#include <stdarg.h>
#include <stdio.h>

typedef struct _PHYSICAL_MEMORY_RUN {
  PFN_NUMBER BasePage;
  PFN_NUMBER PageCount;
} PHYSICAL_MEMORY_RUN, *PPHYSICAL_MEMORY_RUN;

typedef struct _PHYSICAL_MEMORY_DESCRIPTOR {
  ULONG NumberOfRuns;
  PFN_NUMBER NumberOfPages;
  PHYSICAL_MEMORY_RUN Run[1]; // NumberOfRuns is the total entries.
} PHYSICAL_MEMORY_DESCRIPTOR, *PPHYSICAL_MEMORY_DESCRIPTOR;

#define MI_CONVERT_PHYSICAL_TO_PFN(Pa) (Pa >> 12)

//
// IOCTL
//
/* This is used to query the driver about memory stats.

   In - Encode the level and method in bits 8-16.
   Out - struct PmemMemroyInfo.
 */
#define IOCTL_GET_INFO CTL_CODE(FILE_DEVICE_UNKNOWN, 0x100, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

// This is the structure which is returned.
#pragma pack(push, 2)

struct PmemMemroyInfo {
  LARGE_INTEGER CR3;
  LARGE_INTEGER KPCR;
  ULONG NumberOfRuns;

  // A Null terminated array of ranges.
  PHYSICAL_MEMORY_RANGE Run[1];
};

/* These should be changed for incident response purposes to prevent trivial
 * rootkit subversion.
 */
#define SILENT_OPERATION 0
#define PMEM_DEVICE_NAME L"pmem"
#define PMEM_VERSION "v1.0"

/* When we are silent we do not emit any debug messages. */
#if SILENT_OPERATION
#define WinDbgPrint(fmt, ...)
#else
#define WinDbgPrint DbgPrint
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

// 5e1ce668-47cb-410e-a664-5c705ae4d71b
DEFINE_GUID(GUID_DEVCLASS_PMEM_DUMPER,
            0x5e1ce668L,
            0x47cb,
            0x410e,
            0xa6, 0x64, 0x5c, 0x70, 0x5a, 0xe4, 0xd7, 0x1b);

#pragma pack(pop)

#endif

