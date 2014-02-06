#include "windows.h"
#include "stdio.h"
#include "tchar.h"
#include "Dump.h"

// Executable version.
static TCHAR version[] = TEXT("1.5.4 Built ") TEXT(__DATE__);
#define PMEM_DEVICE_NAME "pmem"
#define PMEM_SERVICE_NAME TEXT("pmem")


// These numbers are set in the resource editor for the FILE resource.
#define WINPMEM_64BIT_DRIVER 104
#define WINPMEM_32BIT_DRIVER 105

#define PAGE_SIZE 0x1000

class WinPmem {
 public:
  WinPmem();
  virtual ~WinPmem();

  virtual int install_driver();
  virtual int uninstall_driver();
  virtual int set_write_enabled();
  virtual int set_acquisition_mode(unsigned __int32 mode);

  virtual void print_memory_info();

  // In order to create an image:

  // 1. Create an output file with create_output_file()
  // 2. Select either write_raw_image() or write_crashdump().
  // 3. When thid object is deleted, the file is closed.
  virtual int create_output_file(TCHAR *output_filename);
  virtual int write_raw_image();
  virtual int write_crashdump();

  // This is set if output should be suppressed (e.g. if we pipe the
  // image to the STDOUT).
  int suppress_output;
  TCHAR last_error[1024];

 protected:
  int extract_file_(int driver_id);
  virtual int load_driver_() = 0;
  virtual int write_crashdump_header_(struct PmemMemoryInfo *info) = 0;

  virtual void LogError(TCHAR *message);
  virtual void Log(const TCHAR *message, ...);

  int pad(__int64 length);
  int copy_memory(unsigned __int64 start, unsigned __int64 end);

  // The file handle to the pmem device.
  HANDLE fd_;

  // The file handle to the image file.
  HANDLE out_fd_;
  TCHAR *service_name;
  char *buffer_;
  size_t buffer_size_;
  TCHAR driver_filename[MAX_PATH];

  // This is the maximum size of memory calculated.
  unsigned __int64 max_physical_memory_;

  // The current acquisition mode.
  unsigned int mode_;
};

class WinPmem32: public WinPmem {
 protected:
  virtual int load_driver_();
  virtual int write_crashdump_header_(struct PmemMemoryInfo *info);
};

class WinPmem64: public WinPmem {
 protected:
  virtual int load_driver_();
  virtual int write_crashdump_header_(struct PmemMemoryInfo *info);
};


// This is the filename of the driver we drop.
static TCHAR driver_filename[MAX_PATH];

// ioctl to get memory ranges from our driver.
#define PMEM_CTRL_IOCTRL CTL_CODE(0x22, 0x101, 0, 3)
#define PMEM_WRITE_ENABLE CTL_CODE(0x22, 0x102, 0, 3)
#define PMEM_INFO_IOCTRL CTL_CODE(0x22, 0x103, 0, 3)

// Available modes
#define PMEM_MODE_IOSPACE 0
#define PMEM_MODE_PHYSICAL 1
#define PMEM_MODE_PTE 2
#define PMEM_MODE_PTE_PCI 3

#pragma pack(push, 2)
typedef struct pmem_info_runs {
  __int64 start;
  __int64 length;
} PHYSICAL_MEMORY_RANGE;

struct PmemMemoryInfo {
  LARGE_INTEGER CR3;
  LARGE_INTEGER NtBuildNumber; // Version of this kernel.
  LARGE_INTEGER KernBase;  // The base of the kernel image.
  LARGE_INTEGER KDBG;  // The address of KDBG

  // Support up to 32 processors for KPCR.
  LARGE_INTEGER KPCR[32];

  LARGE_INTEGER PfnDataBase;
  LARGE_INTEGER PsLoadedModuleList;
  LARGE_INTEGER PsActiveProcessHead;

  // As the driver is extended we can add fields here maintaining
  // driver alignment..
  LARGE_INTEGER Padding[0xff];

  LARGE_INTEGER NumberOfRuns;

  // A Null terminated array of ranges.
  PHYSICAL_MEMORY_RANGE Run[100];
};

#pragma pack(pop)

//
// This structure is used by the debugger for all targets
// It is the same size as DBGKD_DATA_HEADER on all systems
//
typedef struct _DBGKD_DEBUG_DATA_HEADER64 {

  //
  // Link to other blocks
  //

  LIST_ENTRY64 List;

  //
  // This is a unique tag to identify the owner of the block.
  // If your component only uses one pool tag, use it for this, too.
  //

  ULONG           OwnerTag;

  //
  // This must be initialized to the size of the data block,
  // including this structure.
  //

  ULONG           Size;

} DBGKD_DEBUG_DATA_HEADER64, *PDBGKD_DEBUG_DATA_HEADER64;

//
// This structure is the same size on all systems.  The only field
// which must be translated by the debugger is Header.List.
//

//
// DO NOT ADD OR REMOVE FIELDS FROM THE MIDDLE OF THIS STRUCTURE!!!
//
// If you remove a field, replace it with an "unused" placeholder.
// Do not reuse fields until there has been enough time for old debuggers
// and extensions to age out.
//
typedef struct _KDDEBUGGER_DATA64 {

  DBGKD_DEBUG_DATA_HEADER64 Header;

  //
  // Base address of kernel image
  //

  ULONG64   KernBase;

  //
  // DbgBreakPointWithStatus is a function which takes an argument
  // and hits a breakpoint.  This field contains the address of the
  // breakpoint instruction.  When the debugger sees a breakpoint
  // at this address, it may retrieve the argument from the first
  // argument register, or on x86 the eax register.
  //

  ULONG64   BreakpointWithStatus;       // address of breakpoint

  //
  // Address of the saved context record during a bugcheck
  //
  // N.B. This is an automatic in KeBugcheckEx's frame, and
  // is only valid after a bugcheck.
  //

  ULONG64   SavedContext;

  //
  // help for walking stacks with user callbacks:
  //

  //
  // The address of the thread structure is provided in the
  // WAIT_STATE_CHANGE packet.  This is the offset from the base of
  // the thread structure to the pointer to the kernel stack frame
  // for the currently active usermode callback.
  //

  USHORT  ThCallbackStack;            // offset in thread data

  //
  // these values are offsets into that frame:
  //

  USHORT  NextCallback;               // saved pointer to next callback frame
  USHORT  FramePointer;               // saved frame pointer

  //
  // pad to a quad boundary
  //
  USHORT  PaeEnabled:1;

  //
  // Address of the kernel callout routine.
  //

  ULONG64   KiCallUserMode;             // kernel routine

  //
  // Address of the usermode entry point for callbacks.
  //

  ULONG64   KeUserCallbackDispatcher;   // address in ntdll


  //
  // Addresses of various kernel data structures and lists
  // that are of interest to the kernel debugger.
  //

  ULONG64   PsLoadedModuleList;
  ULONG64   PsActiveProcessHead;
  ULONG64   PspCidTable;

  ULONG64   ExpSystemResourcesList;
  ULONG64   ExpPagedPoolDescriptor;
  ULONG64   ExpNumberOfPagedPools;

  ULONG64   KeTimeIncrement;
  ULONG64   KeBugCheckCallbackListHead;
  ULONG64   KiBugcheckData;

  ULONG64   IopErrorLogListHead;

  ULONG64   ObpRootDirectoryObject;
  ULONG64   ObpTypeObjectType;

  ULONG64   MmSystemCacheStart;
  ULONG64   MmSystemCacheEnd;
  ULONG64   MmSystemCacheWs;

  ULONG64   MmPfnDatabase;
  ULONG64   MmSystemPtesStart;
  ULONG64   MmSystemPtesEnd;
  ULONG64   MmSubsectionBase;
  ULONG64   MmNumberOfPagingFiles;

  ULONG64   MmLowestPhysicalPage;
  ULONG64   MmHighestPhysicalPage;
  ULONG64   MmNumberOfPhysicalPages;

  ULONG64   MmMaximumNonPagedPoolInBytes;
  ULONG64   MmNonPagedSystemStart;
  ULONG64   MmNonPagedPoolStart;
  ULONG64   MmNonPagedPoolEnd;

  ULONG64   MmPagedPoolStart;
  ULONG64   MmPagedPoolEnd;
  ULONG64   MmPagedPoolInformation;
  ULONG64   MmPageSize;

  ULONG64   MmSizeOfPagedPoolInBytes;

  ULONG64   MmTotalCommitLimit;
  ULONG64   MmTotalCommittedPages;
  ULONG64   MmSharedCommit;
  ULONG64   MmDriverCommit;
  ULONG64   MmProcessCommit;
  ULONG64   MmPagedPoolCommit;
  ULONG64   MmExtendedCommit;

  ULONG64   MmZeroedPageListHead;
  ULONG64   MmFreePageListHead;
  ULONG64   MmStandbyPageListHead;
  ULONG64   MmModifiedPageListHead;
  ULONG64   MmModifiedNoWritePageListHead;
  ULONG64   MmAvailablePages;
  ULONG64   MmResidentAvailablePages;

  ULONG64   PoolTrackTable;
  ULONG64   NonPagedPoolDescriptor;

  ULONG64   MmHighestUserAddress;
  ULONG64   MmSystemRangeStart;
  ULONG64   MmUserProbeAddress;

  ULONG64   KdPrintCircularBuffer;
  ULONG64   KdPrintCircularBufferEnd;
  ULONG64   KdPrintWritePointer;
  ULONG64   KdPrintRolloverCount;

  ULONG64   MmLoadedUserImageList;

  // NT 5.1 Addition

  ULONG64   NtBuildLab;
  ULONG64   KiNormalSystemCall;

  // NT 5.0 hotfix addition

  ULONG64   KiProcessorBlock;
  ULONG64   MmUnloadedDrivers;
  ULONG64   MmLastUnloadedDriver;
  ULONG64   MmTriageActionTaken;
  ULONG64   MmSpecialPoolTag;
  ULONG64   KernelVerifier;
  ULONG64   MmVerifierData;
  ULONG64   MmAllocatedNonPagedPool;
  ULONG64   MmPeakCommitment;
  ULONG64   MmTotalCommitLimitMaximum;
  ULONG64   CmNtCSDVersion;

  // NT 5.1 Addition

  ULONG64   MmPhysicalMemoryBlock;
  ULONG64   MmSessionBase;
  ULONG64   MmSessionSize;
  ULONG64   MmSystemParentTablePage;

  // Server 2003 addition

  ULONG64   MmVirtualTranslationBase;

  USHORT    OffsetKThreadNextProcessor;
  USHORT    OffsetKThreadTeb;
  USHORT    OffsetKThreadKernelStack;
  USHORT    OffsetKThreadInitialStack;

  USHORT    OffsetKThreadApcProcess;
  USHORT    OffsetKThreadState;
  USHORT    OffsetKThreadBStore;
  USHORT    OffsetKThreadBStoreLimit;

  USHORT    SizeEProcess;
  USHORT    OffsetEprocessPeb;
  USHORT    OffsetEprocessParentCID;
  USHORT    OffsetEprocessDirectoryTableBase;

  USHORT    SizePrcb;
  USHORT    OffsetPrcbDpcRoutine;
  USHORT    OffsetPrcbCurrentThread;
  USHORT    OffsetPrcbMhz;

  USHORT    OffsetPrcbCpuType;
  USHORT    OffsetPrcbVendorString;
  USHORT    OffsetPrcbProcStateContext;
  USHORT    OffsetPrcbNumber;

  USHORT    SizeEThread;

  ULONG64   KdPrintCircularBufferPtr;
  ULONG64   KdPrintBufferSize;

  ULONG64   KeLoaderBlock;

  USHORT    SizePcr;
  USHORT    OffsetPcrSelfPcr;
  USHORT    OffsetPcrCurrentPrcb;
  USHORT    OffsetPcrContainedPrcb;

  USHORT    OffsetPcrInitialBStore;
  USHORT    OffsetPcrBStoreLimit;
  USHORT    OffsetPcrInitialStack;
  USHORT    OffsetPcrStackLimit;

  USHORT    OffsetPrcbPcrPage;
  USHORT    OffsetPrcbProcStateSpecialReg;
  USHORT    GdtR0Code;
  USHORT    GdtR0Data;

  USHORT    GdtR0Pcr;
  USHORT    GdtR3Code;
  USHORT    GdtR3Data;
  USHORT    GdtR3Teb;

  USHORT    GdtLdt;
  USHORT    GdtTss;
  USHORT    Gdt64R3CmCode;
  USHORT    Gdt64R3CmTeb;

  ULONG64   IopNumTriageDumpDataBlocks;
  ULONG64   IopTriageDumpDataBlocks;

  // Longhorn addition

  ULONG64   VfCrashDataBlock;
  ULONG64   MmBadPagesDetected;
  ULONG64   MmZeroedPageSingleBitErrorsDetected;

  // Windows 7 addition

  ULONG64   EtwpDebuggerData;
  USHORT    OffsetPrcbContext;

} KDDEBUGGER_DATA64, *PKDDEBUGGER_DATA64;
