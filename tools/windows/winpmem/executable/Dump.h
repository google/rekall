////////////////////////////////////////////////////////////////////////////////
//
//  Microsoft Research Singularity
//
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//
//  File:   Dump.h
//
//  Note:   Constants and types for kernel dump files.
//
// This file came from https://singularity.svn.codeplex.com/svn/base/Windows/Inc/Dump.h

#pragma warning(push)
#pragma warning(disable : 4200) // don't warn about zero-sized array in struct/union

typedef struct _STRING64 {
    USHORT   Length;
    USHORT   MaximumLength;
    ULONGLONG  Buffer;
} STRING64;
typedef STRING64 *PSTRING64;

typedef STRING64 UNICODE_STRING64;
typedef UNICODE_STRING64 *PUNICODE_STRING64;


#ifdef __cplusplus
extern "C" {
#endif

#define USERMODE_CRASHDUMP_SIGNATURE    'RESU'
#define USERMODE_CRASHDUMP_VALID_DUMP32 'PMUD'
#define USERMODE_CRASHDUMP_VALID_DUMP64 '46UD'

typedef struct _USERMODE_CRASHDUMP_HEADER64 {
    ULONG       Signature;
    ULONG       ValidDump;
    ULONG       MajorVersion;
    ULONG       MinorVersion;
    ULONG       MachineImageType;
    ULONG       ThreadCount;
    ULONG       ModuleCount;
    ULONG       MemoryRegionCount;
    ULONGLONG   ThreadOffset;
    ULONGLONG   ModuleOffset;
    ULONGLONG   DataOffset;
    ULONGLONG   MemoryRegionOffset;
    ULONGLONG   DebugEventOffset;
    ULONGLONG   ThreadStateOffset;
    ULONGLONG   VersionInfoOffset;
    ULONGLONG   Spare1;
} USERMODE_CRASHDUMP_HEADER64, *PUSERMODE_CRASHDUMP_HEADER64;

typedef struct _CRASH_MODULE64 {
    ULONGLONG   BaseOfImage;
    ULONG       SizeOfImage;
    ULONG       ImageNameLength;
    CHAR        ImageName[0];
} CRASH_MODULE64, *PCRASH_MODULE64;

typedef struct _CRASH_THREAD64 {
    ULONG       ThreadId;
    ULONG       SuspendCount;
    ULONG       PriorityClass;
    ULONG       Priority;
    ULONGLONG   Teb;
    ULONGLONG   Spare0;
    ULONGLONG   Spare1;
    ULONGLONG   Spare2;
    ULONGLONG   Spare3;
    ULONGLONG   Spare4;
    ULONGLONG   Spare5;
    ULONGLONG   Spare6;
} CRASH_THREAD64, *PCRASH_THREAD64;

typedef struct _CRASHDUMP_VERSION_INFO {
    int     IgnoreGuardPages;       // Whether we should ignore GuardPages or not
    ULONG   PointerSize;            // 32, 64 bit pointers
} CRASHDUMP_VERSION_INFO, *PCRASHDUMP_VERSION_INFO;

//
// usermode crash dump data types
//
#define DMP_EXCEPTION                 1 // obsolete
#define DMP_MEMORY_BASIC_INFORMATION  2
#define DMP_THREAD_CONTEXT            3
#define DMP_MODULE                    4
#define DMP_MEMORY_DATA               5
#define DMP_DEBUG_EVENT               6
#define DMP_THREAD_STATE              7
#define DMP_DUMP_FILE_HANDLE          8

//
// Define the information required to process memory dumps.
//


typedef enum _DUMP_TYPES {
    DUMP_TYPE_INVALID           = -1,
    DUMP_TYPE_UNKNOWN           = 0,
    DUMP_TYPE_FULL              = 1,
    DUMP_TYPE_SUMMARY           = 2,
    DUMP_TYPE_HEADER            = 3,
    DUMP_TYPE_TRIAGE            = 4,
} DUMP_TYPE;


//
// Signature and Valid fields.
//

#define DUMP_SIGNATURE32   ('EGAP')
#define DUMP_VALID_DUMP32  ('PMUD')

#define DUMP_SIGNATURE64   ('EGAP')
#define DUMP_VALID_DUMP64  ('46UD')

#define DUMP_SUMMARY_SIGNATURE  ('PMDS')
#define DUMP_SUMMARY_VALID      ('PMUD')

#define DUMP_SUMMARY_VALID_KERNEL_VA                     (1)
#define DUMP_SUMMARY_VALID_CURRENT_USER_VA               (2)

 //
 //
 // NOTE: The definition of PHYISCAL_MEMORY_RUN and PHYSICAL_MEMORY_DESCRIPTOR
 // MUST be the same as in mm.h. The kernel portion of crashdump will
 // verify that these structs are the same.
 //

 typedef struct _PHYSICAL_MEMORY_RUN64 {
   ULONG64 BasePage;
   ULONG64 PageCount;
 } PHYSICAL_MEMORY_RUN64, *PPHYSICAL_MEMORY_RUN64;

 typedef struct _PHYSICAL_MEMORY_DESCRIPTOR64 {
   ULONG NumberOfRuns;
   ULONG64 NumberOfPages;
   PHYSICAL_MEMORY_RUN64 Run[1];
 } PHYSICAL_MEMORY_DESCRIPTOR64, *PPHYSICAL_MEMORY_DESCRIPTOR64;

 typedef struct _PHYSICAL_MEMORY_RUN {
   ULONG BasePage;
   ULONG PageCount;
 } PHYSICAL_MEMORY_RUN, *PPHYSICAL_MEMORY_RUN;

 typedef struct _PHYSICAL_MEMORY_DESCRIPTOR {
   ULONG NumberOfRuns;
   ULONG NumberOfPages;
   PHYSICAL_MEMORY_RUN Run[1];
 } PHYSICAL_MEMORY_DESCRIPTOR, *PPHYSICAL_MEMORY_DESCRIPTOR;

 typedef struct _UNLOADED_DRIVERS64 {
   UNICODE_STRING64 Name;
   ULONG64 StartAddress;
   ULONG64 EndAddress;
   LARGE_INTEGER CurrentTime;
 } UNLOADED_DRIVERS64, *PUNLOADED_DRIVERS64;

#define MAX_UNLOADED_NAME_LENGTH 24

 typedef struct _DUMP_UNLOADED_DRIVERS64
 {
   UNICODE_STRING64 Name;
   WCHAR DriverName[MAX_UNLOADED_NAME_LENGTH / sizeof (WCHAR)];
   ULONG64 StartAddress;
   ULONG64 EndAddress;
 } DUMP_UNLOADED_DRIVERS64, *PDUMP_UNLOADED_DRIVERS64;

 typedef struct _DUMP_MM_STORAGE64
 {
   ULONG Version;
   ULONG Size;
   ULONG MmSpecialPoolTag;
   ULONG MiTriageActionTaken;

   ULONG MmVerifyDriverLevel;
   ULONG KernelVerifier;
   ULONG64 MmMaximumNonPagedPool;
   ULONG64 MmAllocatedNonPagedPool;

   ULONG64 PagedPoolMaximum;
   ULONG64 PagedPoolAllocated;

   ULONG64 CommittedPages;
   ULONG64 CommittedPagesPeak;
   ULONG64 CommitLimitMaximum;
 } DUMP_MM_STORAGE64, *PDUMP_MM_STORAGE64;


 //
 // Define the dump header structure. You cannot change these
 // defines without breaking the debuggers, so don't.
 //

#define DMP_PHYSICAL_MEMORY_BLOCK_SIZE_32   (700)
#define DMP_CONTEXT_RECORD_SIZE_32          (1200)
#define DMP_RESERVED_0_SIZE_32              (1768)
#define DMP_RESERVED_2_SIZE_32              (16)
#define DMP_RESERVED_3_SIZE_32              (56)

#define DMP_PHYSICAL_MEMORY_BLOCK_SIZE_64   (700)
#define DMP_CONTEXT_RECORD_SIZE_64          (3000)
#define DMP_RESERVED_0_SIZE_64              (4016)

#define DMP_HEADER_COMMENT_SIZE             (128)

 // Unset WriterStatus value from the header fill.
#define DUMP_WRITER_STATUS_UNINITIALIZED    DUMP_SIGNATURE32

 // WriterStatus codes for the dbgeng.dll dump writers.
enum {
  DUMP_DBGENG_SUCCESS,
  DUMP_DBGENG_NO_MODULE_LIST,
  DUMP_DBGENG_CORRUPT_MODULE_LIST,
};

// 32 bit header taken from win32dd source.
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
  ULONG KdDebuggerDataBlock;
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

typedef struct _DUMP_HEADER64 {
    ULONG Signature;
    ULONG ValidDump;
    ULONG MajorVersion;
    ULONG MinorVersion;
    ULONG64 DirectoryTableBase;
    ULONG64 PfnDataBase;
    ULONG64 PsLoadedModuleList;
    ULONG64 PsActiveProcessHead;
    ULONG MachineImageType;
    ULONG NumberProcessors;
    ULONG BugCheckCode;
    ULONG64 BugCheckParameter1;
    ULONG64 BugCheckParameter2;
    ULONG64 BugCheckParameter3;
    ULONG64 BugCheckParameter4;
    CHAR VersionUser[32];
    ULONG64 KdDebuggerDataBlock;

    union {
        PHYSICAL_MEMORY_DESCRIPTOR64 PhysicalMemoryBlock;
        UCHAR PhysicalMemoryBlockBuffer [ DMP_PHYSICAL_MEMORY_BLOCK_SIZE_64 ];
    };
    UCHAR ContextRecord [ DMP_CONTEXT_RECORD_SIZE_64 ];
    EXCEPTION_RECORD64 Exception;
    ULONG DumpType;
    LARGE_INTEGER RequiredDumpSpace;
    LARGE_INTEGER SystemTime;
    CHAR Comment [ DMP_HEADER_COMMENT_SIZE ];   // May not be present.
    LARGE_INTEGER SystemUpTime;
    ULONG MiniDumpFields;
    ULONG SecondaryDataState;
    ULONG ProductType;
    ULONG SuiteMask;
    ULONG WriterStatus;
    UCHAR Unused1;
    UCHAR KdSecondaryVersion;       // Present only for W2K3 SP1 and better
    UCHAR Unused[2];
    UCHAR _reserved0[ DMP_RESERVED_0_SIZE_64 ];
} DUMP_HEADER64, *PDUMP_HEADER64;

typedef struct _FULL_DUMP64 {
    CHAR Memory[1];             // Variable length to the end of the dump file.
} FULL_DUMP64, *PFULL_DUMP64;

//
// ISSUE - 2000/02/17 - math: NT64 Summary dump.
//
// This is broken. The 64 bit summary dump should have a ULONG64 for
// the BitmapSize to match the size of the PFN_NUMBER.
//

typedef struct _SUMMARY_DUMP64 {
    ULONG Signature;
    ULONG ValidDump;
    ULONG DumpOptions;  // Summary Dump Options
    ULONG HeaderSize;   // Offset to the start of actual memory dump
    ULONG BitmapSize;   // Total bitmap size (i.e., maximum #bits)
    ULONG Pages;        // Total bits set in bitmap (i.e., total pages in sdump)

    //
    // ISSUE - 2000/02/17 - math: Win64
    //
    // With a 64-bit PFN, we should not have a 32-bit bitmap.
    //

    //
    // These next three fields essentially form an on-disk RTL_BITMAP structure.
    // The RESERVED field is stupidness introduced by the way the data is
    // serialized to disk.
    //

    struct {
        ULONG SizeOfBitMap;
        ULONG64 _reserved0;
        ULONG Buffer[];
    } Bitmap;

} SUMMARY_DUMP64, * PSUMMARY_DUMP64;


typedef struct _TRIAGE_DUMP64 {
    ULONG ServicePackBuild;             // What service pack of NT was this ?
    ULONG SizeOfDump;                   // Size in bytes of the dump
    ULONG ValidOffset;                  // Offset valid ULONG
    ULONG ContextOffset;                // Offset of CONTEXT record
    ULONG ExceptionOffset;              // Offset of EXCEPTION record
    ULONG MmOffset;                     // Offset of Mm information
    ULONG UnloadedDriversOffset;        // Offset of Unloaded Drivers
    ULONG PrcbOffset;                   // Offset of KPRCB
    ULONG ProcessOffset;                // Offset of EPROCESS
    ULONG ThreadOffset;                 // Offset of ETHREAD
    ULONG CallStackOffset;              // Offset of CallStack Pages
    ULONG SizeOfCallStack;              // Size in bytes of CallStack
    ULONG DriverListOffset;             // Offset of Driver List
    ULONG DriverCount;                  // Number of Drivers in list
    ULONG StringPoolOffset;             // Offset to the string pool
    ULONG StringPoolSize;               // Size of the string pool
    ULONG BrokenDriverOffset;           // Offset into the driver of the driver that crashed
    ULONG TriageOptions;                // Triage options in effect at crashtime
    ULONG64 TopOfStack;                 // The top (highest address) of the callstack

    //
    // Architecture Specific fields.
    //

    union {

        //
        // For IA64 we need to store the BStore as well.
        //

        struct {
            ULONG BStoreOffset;         // Offset of BStore region.
            ULONG SizeOfBStore;         // The size of the BStore region.
            ULONG64 LimitOfBStore;      // The limit (highest memory address)
        } Ia64;                         //  of the BStore region.

    } ArchitectureSpecific;

    ULONG64 DataPageAddress;
    ULONG   DataPageOffset;
    ULONG   DataPageSize;

    ULONG   DebuggerDataOffset;
    ULONG   DebuggerDataSize;

    ULONG   DataBlocksOffset;
    ULONG   DataBlocksCount;

} TRIAGE_DUMP64, * PTRIAGE_DUMP64;


typedef struct _MEMORY_DUMP64 {
    DUMP_HEADER64 Header;

    union {
        FULL_DUMP64 Full;               // DumpType == DUMP_TYPE_FULL
        SUMMARY_DUMP64 Summary;         // DumpType == DUMP_TYPE_SUMMARY
        TRIAGE_DUMP64 Triage;           // DumpType == DUMP_TYPE_TRIAGE
    };

} MEMORY_DUMP64, *PMEMORY_DUMP64;


typedef struct _TRIAGE_DATA_BLOCK {
    ULONG64 Address;
    ULONG Offset;
    ULONG Size;
} TRIAGE_DATA_BLOCK, *PTRIAGE_DATA_BLOCK;

//
// In the triage dump ValidFields field what portions of the triage-dump have
// been turned on.
//

#define TRIAGE_DUMP_CONTEXT          (0x0001)
#define TRIAGE_DUMP_EXCEPTION        (0x0002)
#define TRIAGE_DUMP_PRCB             (0x0004)
#define TRIAGE_DUMP_PROCESS          (0x0008)
#define TRIAGE_DUMP_THREAD           (0x0010)
#define TRIAGE_DUMP_STACK            (0x0020)
#define TRIAGE_DUMP_DRIVER_LIST      (0x0040)
#define TRIAGE_DUMP_BROKEN_DRIVER    (0x0080)
#define TRIAGE_DUMP_BASIC_INFO       (0x00FF)
#define TRIAGE_DUMP_MMINFO           (0x0100)
#define TRIAGE_DUMP_DATAPAGE         (0x0200)
#define TRIAGE_DUMP_DEBUGGER_DATA    (0x0400)
#define TRIAGE_DUMP_DATA_BLOCKS      (0x0800)

#define TRIAGE_OPTION_OVERFLOWED     (0x0100)

#define TRIAGE_DUMP_VALID       ( 'DGRT' )
#define TRIAGE_DUMP_SIZE32      ( 0x1000 * 16 )
#define TRIAGE_DUMP_SIZE64      ( 0x2000 * 16 )

//
// The DUMP_STRING is guaranteed to be both NULL terminated and length prefixed
// (prefix does not include the NULL).
//

typedef struct _DUMP_STRING {
    ULONG Length;                   // Length IN BYTES of the string.
    WCHAR Buffer [0];               // Buffer.
} DUMP_STRING, * PDUMP_STRING;


#ifdef __cplusplus
}
#endif

#pragma warning(pop)
