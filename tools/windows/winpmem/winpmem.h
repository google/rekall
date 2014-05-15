/*
   Copyright 2012 Michael Cohen <scudette@gmail.com>

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

/* These should be changed for incident response purposes to prevent trivial
 * rootkit subversion.
 */
#define SILENT_OPERATION 0
#define PMEM_DEVICE_NAME L"pmem"
#define PMEM_VERSION "v1.6.0"
#define PMEM_POOL_TAG 0x4d454d50

// In order to enable writing this must be set to 1 and the
// appropriate IOCTL must be sent to switch the driver to write mode.
#define PMEM_WRITE_ENABLED 0

#include <ntifs.h>
#include <wdmsec.h>
#include <initguid.h>
#include <stdarg.h>
#include <stdio.h>

#include "pte_mmap.h"
#include "api.h"

// Some standard integer sizes.
typedef unsigned __int64 u64;
typedef unsigned __int32 u32;
typedef unsigned __int16 u16;
typedef unsigned __int8 u8;

#define MI_CONVERT_PHYSICAL_TO_PFN(Pa) (Pa >> 12)

//
// IOCTL
//
// This is used to query the driver about memory stats.
#define IOCTL_GET_INFO CTL_CODE(FILE_DEVICE_UNKNOWN, 0x103, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

#define IOCTL_SET_MODE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x101, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

#define IOCTL_WRITE_ENABLE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x102, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

// This is the old deprecated interface. Use IOCTL_GET_INFO instead.
#define IOCTL_GET_INFO_DEPRECATED CTL_CODE(FILE_DEVICE_UNKNOWN, 0x100, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

// This is the structure which is returned.
#pragma pack(push, 2)

extern PUSHORT NtBuildNumber;

/* This is the format of the deprecated IOCTL_GET_INFO_DEPRECATED
   call.
*/
struct DeprecatedPmemMemoryInfo {
  LARGE_INTEGER CR3;
  LARGE_INTEGER KPCR;
  ULONG NumberOfRuns;

  // A Null terminated array of ranges.
  PHYSICAL_MEMORY_RANGE Run[1];
};



struct PmemMemoryInfo {
  LARGE_INTEGER CR3;
  LARGE_INTEGER NtBuildNumber; // Version of this kernel.

  LARGE_INTEGER KernBase;  // The base of the kernel image.

  // The following are deprecated and will not be set by the driver. It is safer
  // to get these during analysis from NtBuildNumberAddr below.
  LARGE_INTEGER KDBG;  // The address of KDBG

  // Support up to 32 processors for KPCR.
  LARGE_INTEGER KPCR[32];

  LARGE_INTEGER PfnDataBase;
  LARGE_INTEGER PsLoadedModuleList;
  LARGE_INTEGER PsActiveProcessHead;

  // END DEPRECATED.

  // The address of the NtBuildNumber integer - this is used to find the kernel
  // base quickly.
  LARGE_INTEGER NtBuildNumberAddr;

  // As the driver is extended we can add fields here maintaining
  // driver alignment..
  LARGE_INTEGER Padding[0xfe];

  LARGE_INTEGER NumberOfRuns;

  // A Null terminated array of ranges.
  PHYSICAL_MEMORY_RANGE Run[1];
};


enum PMEM_ACQUISITION_MODE {
  // Use the MmMapIoSpace API.
  ACQUISITION_MODE_MAP_IO_SPACE = 0,

  // Map the \\.\PhysicalMemory device.
  ACQUISITION_MODE_PHYSICAL_MEMORY = 1,

  // Use direct page table manipulation.
  ACQUISITION_MODE_PTE_MMAP = 2,

  // Use direct page table manipulation with PCI memory map probing
  ACQUISITION_MODE_PTE_MMAP_WITH_PCI_PROBE = 3
};

struct PmemMemoryControl {
  u32 mode;    //really: enum PMEM_ACQUISITION_MODE mode but we want to enforce
               //standard struct sizes.;
};


/* When we are silent we do not emit any debug messages. */
#if SILENT_OPERATION == 1
#define WinDbgPrint(fmt, ...)
#define vWinDbgPrintEx(x, ...)
#else
#define WinDbgPrint DbgPrint
#define vWinDbgPrintEx vDbgPrintEx
#endif

// Add verbose debugging to PCI code.
#define WINPMEM_PCI_DEBUG 0


/*
  Our Device Extension Structure.
*/
typedef struct _DEVICE_EXTENSION {
  /* How we should acquire memory. */
  enum WDD_ACQUISITION_MODE mode;

  /* If we read from \\Device\\PhysicalMemory, this is the handle to that. */
  HANDLE MemoryHandle;

  int WriteEnabled;

  /* Hold a handle to the pte_mmap object. */
  PTE_MMAP_OBJ *pte_mmapper;
} DEVICE_EXTENSION, *PDEVICE_EXTENSION;

// 5e1ce668-47cb-410e-a664-5c705ae4d71b
DEFINE_GUID(GUID_DEVCLASS_PMEM_DUMPER,
            0x5e1ce668L,
            0x47cb,
            0x410e,
            0xa6, 0x64, 0x5c, 0x70, 0x5a, 0xe4, 0xd7, 0x1b);

#pragma pack(pop)

#endif
