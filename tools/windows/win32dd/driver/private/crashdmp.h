/*++

Copyright (c) 2008  Matthieu Suiche

Module Name:

    io.h

Abstract:

    This file contains private structure and define used by NT I/O.

Author:

    Matthieu Suiche (msuiche) 24-aug-2008

Environment:

    Kernel mode

Revision History:


--*/

#ifndef _CRSHDMP_H_
#define _CRSHDMP_H_

#include "mm.h"
#include "kd.h"

//
// Defines
//


//
// Internals
//
#define IO_TYPE_DCB 0xff

#define DCB_DUMP_ENABLED 0x01

#define CR4_PAE 0x00000020

//
// File header declaration
//
//
// Full physical memory snapshot
//
#define DUMP_TYPE_FULL 1

#define IMAGE_FILE_MACHINE_I386 0x014c
#define CURRENT_IMAGE_TYPE() IMAGE_FILE_MACHINE_I386
#define PaeEnabled() MiX86PaeEnabled()

#define DUMP_TAG 'pumD'


//
// Call back routines
//
typedef
VOID
(*PSTALL_ROUTINE)(
    IN ULONG Delay
);

typedef
BOOLEAN
(*PDUMP_DRIVER_OPEN)(
    IN LARGE_INTEGER Offset
);

typedef
NTSTATUS
(*PDUMP_DRIVER_WRITE)(
    IN PLARGE_INTEGER Offset,
    IN PMDL Mdl
);

typedef
VOID
(*PDUMP_DRIVER_FINISH)(
    VOID
);

typedef
NTSTATUS
(*PDUMP_DRIVER_WRITE_PENDING)(
    IN ULONG Count,
    IN PLARGE_INTEGER Offset,
    IN PMDL Mdl,
    IN PVOID Data
);

//
// Structures
//
typedef struct _DUMP_INITIALIZATION_CONTEXT
{
    ULONG Length;
    ULONG Reserved;
    PVOID MemoryBlock;
    PVOID CommonBuffer[2];
    PHYSICAL_ADDRESS PhysicalAddress[2];
    PSTALL_ROUTINE StallRoutine;
    PDUMP_DRIVER_OPEN OpenRoutine;
    PDUMP_DRIVER_WRITE WriteRoutine;
    PDUMP_DRIVER_FINISH FinishRoutine;
    PVOID AdapterObject; // hal.dll define
    PVOID MappedRegisterBase;
    PVOID PortConfiguration;
    BOOLEAN CrashDump;
    ULONG MaximumTransferSize;
    ULONG CommonBufferSize;
    PVOID TargetAddress;
    PDUMP_DRIVER_WRITE_PENDING WritePendingRoutine;
    ULONG PartitionStyle;
    union
    {
        struct
        {
            ULONG Signature;
            ULONG CheckSum;
        } Mbr;
        struct
        {
            GUID DiskId;
        } Gpt;
    } DiskInfo;
} DUMP_INITIALIZATION_CONTEXT, *PDUMP_INITIALIZATION_CONTEXT;


/*
typedef enum _DEVICE_USAGE_NOTIFICATION_TYPE
{
         DeviceUsageTypeUndefined = 0,
         DeviceUsageTypePaging = 1,
         DeviceUsageTypeHibernation = 2,
         DeviceUsageTypeDumpFile = 3
} DEVICE_USAGE_NOTIFICATION_TYPE;
*/

typedef struct _DUMP_STACK_CONTEXT
{
     DUMP_INITIALIZATION_CONTEXT Init;
     LARGE_INTEGER PartitionOffset;
     PVOID DumpPointers;
     ULONG PointersLength;
     PUSHORT ModulePrefix;
     LIST_ENTRY DriverList;
     STRING InitMsg;
     STRING ProgMsg;
     STRING DoneMsg;
     PVOID FileObject;
     DEVICE_USAGE_NOTIFICATION_TYPE UsageType;
} DUMP_STACK_CONTEXT, *PDUMP_STACK_CONTEXT;


typedef struct _DUMP_HEADER {
    ULONG Signature;
    ULONG ValidDump;
    ULONG MajorVersion;
    ULONG MinorVersion;
    ULONG DirectoryTableBase;
    PULONG PfnDataBase;
    PLIST_ENTRY PsLoadedModuleList;
    PLIST_ENTRY PsActiveProcessHead;
    ULONG MachineImageType;
    ULONG KeNumberOfProcessors;
    ULONG BugCheckCode;
    ULONG BugCheckParameter1;
    ULONG BugCheckParameter2;
    ULONG BugCheckParameter3;
    ULONG BugCheckParameter4;
    CHAR VersionUser[32];
    CHAR PaeEnabled;
    CHAR KdSecondaryVersion;
    CHAR spare[2];
    PKDDEBUGGER_DATA64 KdDebuggerDataBlock;
    PHYSICAL_MEMORY_DESCRIPTOR PhysicalMemoryBlock;
                                        // 29 * sizeof(ULONG)
    ULONG u074[171];
    CONTEXT Context;                    // 0x2CC bytes + 0x320
    ULONG u5EC[121];                    // Enough space to extend the context.
    EXCEPTION_RECORD ExceptionRecord;   // + 0x7D0
    ULONG u820[474];
    ULONG DumpType;                     // 0xF88
    ULONG uF8C[5];
    LARGE_INTEGER RequiredDumpSpace;
    ULONG uFA8[6];
    LARGE_INTEGER SystemTime;
} DUMP_HEADER, *PDUMP_HEADER;

typedef struct _DUMP_CONTROL_BLOCK {
    UCHAR Type;
    CHAR Flags;
    USHORT Size;
    UCHAR KeNumberProcessors;
    CHAR Reserved;
    USHORT ProcessorArchitecture;
    PDUMP_STACK_CONTEXT DumpStack;
    PPHYSICAL_MEMORY_DESCRIPTOR MemoryDescriptor;
    ULONG MemoryDescriptorLength;
    PLARGE_INTEGER FileDescriptorArray;
    ULONG FileDescriptorSize;
    PDUMP_HEADER HeaderPage;
    PFN_NUMBER HeaderPfn;
    ULONG MajorVersion;
    ULONG MinorVersion;
    ULONG BuildNumber;
    CHAR VersionUser[32];
    ULONG HeaderSize;
    LARGE_INTEGER DumpFileSize;
    ULONG TriageDumpFlags;
    PUCHAR TriageDumpBuffer;
    ULONG TriageDumpBufferSize;
} DUMP_CONTROL_BLOCK, *PDUMP_CONTROL_BLOCK;

//
// Global variables
//
extern PDUMP_CONTROL_BLOCK IopDumpControlBlock;

//
// Kernel import
//
extern PULONG NtBuildNumber;

//
// Functions
//

LARGE_INTEGER
IopCalculateRequiredDumpSpace(
    IN ULONG DmpFlags,
    IN ULONG HeaderSize,
    IN PFN_NUMBER MaxPages
);

BOOLEAN
IopInitializeDCB(
);

VOID
IopFreeDCB(BOOLEAN FreeDCB
);

NTSTATUS
IopInitializeDumpSpaceAndType(
    IN PDUMP_CONTROL_BLOCK Dcb,
    IN OUT PDUMP_HEADER DumpHeader
);

#endif _CRSHDMP_H_