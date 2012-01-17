/*++

Copyright (c) 2008  Matthieu Suiche

Module Name:

    crashdmp.c

Abstract:

    All functions to generate a crash dump to disk are in this file.

Author:

    Matthieu Suiche (msuiche) 24-aug-2008

Environment:

    Kernel mode

Revision History:


--*/

#include "precomp.h"

PDUMP_CONTROL_BLOCK IopDumpControlBlock;
PKDDEBUGGER_DATA64 KdVersionBlock;
//PUCHAR NullPage;

NTSTATUS
IopInitializeDumpSpaceAndType(IN PDUMP_CONTROL_BLOCK Dcb,
                              IN OUT PDUMP_HEADER DumpHeader)
{
LARGE_INTEGER Space;

    Space.QuadPart = 0;

    Space = IopCalculateRequiredDumpSpace(Dcb->Flags,
                                          Dcb->HeaderSize,
                                          Dcb->MemoryDescriptor->NumberOfPages);

    DumpHeader->RequiredDumpSpace.LowPart = Space.LowPart;
    DumpHeader->RequiredDumpSpace.HighPart = Space.HighPart;

    return STATUS_SUCCESS;
}

LARGE_INTEGER
IopCalculateRequiredDumpSpace(IN ULONG DmpFlags,
                              IN ULONG HeaderSize,
                              IN PFN_NUMBER MaxPages)
{
LARGE_INTEGER MaxMemorySize;

    MaxMemorySize.QuadPart = (MaxPages * PAGE_SIZE) + HeaderSize;

    return MaxMemorySize;
}



BOOLEAN
IopInitializeDCB(
                )
{
PPHYSICAL_MEMORY_DESCRIPTOR MmPhysicalMemoryBlock;
PDUMP_CONTROL_BLOCK Dcb;
LARGE_INTEGER Page;

PVOID HeaderPage;

ULONG MajorVersion, MinorVersion, BuildNumber;

KAFFINITY ActiveProcessors;

    KdVersionBlock = KdGetDebuggerDataBlock();
    if (KdVersionBlock == NULL)
    {
        DbgPrint("Invalid KdVersionBlock\n");
        return FALSE;
    }

    //
    // Allocate dump control block buffer.
    //
    Dcb = ExAllocatePoolWithTag(NonPagedPool, sizeof(DUMP_CONTROL_BLOCK), DUMP_TAG);

    //
    // Invalid dump control block.
    //
    if (!Dcb)
    {
        DbgPrint("IopInitializeDCB: Cannot allocate pool for DCB\n");
        return FALSE;
    }

    RtlZeroMemory(Dcb, sizeof(DUMP_CONTROL_BLOCK));

    Dcb->Type = IO_TYPE_DCB;
    Dcb->Size = (USHORT)sizeof(DUMP_CONTROL_BLOCK);
    Dcb->Flags = DCB_DUMP_ENABLED;

    //
    // Device drivers can call the KeQueryActiveProcessorCount function to retrieve
    // the current number of active processors in the system. Device drivers that are 
    // built for Windows Vista and later versions of Windows must not use the 
    // KeNumberProcessors kernel variable for this purpose. 
    // BUT! This functions doesn't exist under Windows XP.
    //
    Dcb->KeNumberProcessors = xxxKeQueryActiveProcessorCount();
    Dcb->ProcessorArchitecture = KeQueryProcessorArchitecture();

    //
    // PsGetVersion is obsolete in Windows XP and later versions 
    // of the operating system. Use RtlGetVersion instead.
    //
    /*
    PsGetVersion(&MajorVersion,
                 &MinorVersion,
                 &BuildNumber, 
                 NULL);
     */
    DbgPrint("NtBuildNumber: %08X\n", *NtBuildNumber);
    Dcb->MinorVersion = (USHORT)(*NtBuildNumber & 0xFFFF);
    Dcb->MajorVersion = (USHORT)((*NtBuildNumber >> 28) & 0xFFFFFFFF); // Temp. (BuildNumber >> 28);
    Dcb->BuildNumber = 0;

    Dcb->TriageDumpFlags = 0;

    Dcb->DumpFileSize.QuadPart = 0;

    //
    // Allocate Memory descriptor.
    //
    // Below XP e.g. Win2K
    if (Dcb->MinorVersion < 2600)
    {
        MmPhysicalMemoryBlock = MmGetPhysicalMemoryBlock();
    }
    else
    {
        MmPhysicalMemoryBlock = (PPHYSICAL_MEMORY_DESCRIPTOR)*((PULONG)KdVersionBlock->MmPhysicalMemoryBlock);
    }

    if (!MmPhysicalMemoryBlock)
    {
        DbgPrint("IopInitializeDCB: Unable to get MmPhysicalMemoryBlock\n");
        ExFreePoolWithTag(Dcb, DUMP_TAG);
        return FALSE;
    }

    Dcb->MemoryDescriptorLength = sizeof(PHYSICAL_MEMORY_DESCRIPTOR) - sizeof(PHYSICAL_MEMORY_RUN) +
                                  (MmPhysicalMemoryBlock->NumberOfRuns * sizeof(PHYSICAL_MEMORY_RUN));

    Dcb->MemoryDescriptor = ExAllocatePoolWithTag(NonPagedPool, Dcb->MemoryDescriptorLength, DUMP_TAG);

    if (!Dcb->MemoryDescriptor)
    {
        ExFreePoolWithTag(Dcb, DUMP_TAG);
        DbgPrint("IopInitializeDCB: Cannot allocate pool for Memory descriptor.\n");
        return FALSE;
    }

    RtlCopyMemory(Dcb->MemoryDescriptor, MmPhysicalMemoryBlock, Dcb->MemoryDescriptorLength);

    if (Dcb->MinorVersion < 2600) ExFreePoolWithTag(MmPhysicalMemoryBlock, '  mM');

    Dcb->HeaderSize = PAGE_SIZE;
    Dcb->HeaderPage = ExAllocatePoolWithTag(NonPagedPool, Dcb->HeaderSize, DUMP_TAG);

    if (!Dcb->HeaderPage)
    {
        ExFreePoolWithTag(Dcb->MemoryDescriptor, DUMP_TAG);
        ExFreePoolWithTag(Dcb, DUMP_TAG);
        DbgPrint("IopInitializeDCB: Cannot allocate pool for file header.\n");
        return FALSE;
    }

    Page = MmGetPhysicalAddress(Dcb->HeaderPage);
    Dcb->HeaderPfn = (ULONG)(Page.QuadPart >> PAGE_SHIFT);

    IopDumpControlBlock = Dcb;

    return TRUE;
}

VOID
IopFreeDCB(BOOLEAN FreeDCB
          )
{
    if (FreeDCB)
    {
        //
        // Free header
        //
        ExFreePoolWithTag(IopDumpControlBlock->HeaderPage, DUMP_TAG);

        //
        // Memory block
        //
        ExFreePoolWithTag(IopDumpControlBlock->MemoryDescriptor, DUMP_TAG);

        //
        // Free private block
        //
        ExFreePoolWithTag(IopDumpControlBlock, DUMP_TAG);
    }
}