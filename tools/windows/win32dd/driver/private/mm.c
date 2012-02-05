/*++
    Kernel Land Physical Memory Dumper
    Copyright (C) 2008 Matthieu Suiche http://www.msuiche.net 

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

    - mm.c

Abstract:

    - This driver aims to provide a full dump of the physical memory (RAM).
    - Because since Windows 2003 SP1, access to \\PhysicalMemory has been disabled from user-land,
      and there are no public 100% kernel dumper. I decide to release mine as an open source project.


Environment:

    - Kernel mode

Revision History:

    - Matthieu Suiche

--*/

#include "precomp.h"
#include "mm.h"
#include "io.h"

/*++
Function Name: MmGetPhysicalMemoryBlock

Overview:
        - This function aims at retrieving MmPhysicalMemoryBlock, regardless
        of the host version.

        The caller has to free the memory block.

        - I suggest to recreate PHYSICAL_MEMORY_DESCRIPTOR with following informations:
         NumberOfPages = sizeof(RAM) >> PAGE_SHIFT
         NumberOfRuns = 1
         BasePage = 1
         PageCount = NumberOfPages - BasePage
         Therefore, by using a single Run we can have a valid PHYSICAL_MEM_DESCRIPTOR.

Parameters:
        - 

Environment:
        - Kernel Mode.

Return Values:
        - PPHYSICAL_MEMORY_DESCRIPTOR
--*/
PPHYSICAL_MEMORY_DESCRIPTOR
MmGetPhysicalMemoryBlock(VOID
                         )
{
PPHYSICAL_MEMORY_DESCRIPTOR MmPhysicalMemoryBlock;
PPHYSICAL_MEMORY_RANGE MmPhysicalMemoryRange;
ULONG MemoryBlockSize;
PFN_NUMBER NumberOfPages;
ULONG NumberOfRuns;
ULONG Run;

    //
    // PHYSICAL_MEMORY_DESCRIPTOR isn't exported into KDDEBUGGER_DATA64
    // NT 5.0 and below. But MmGetPhysicalMemoryRanges() computes
    // PHYSICAL_MEMORY_RANGE with PHYSICAL_MEMORY_DESCRIPTOR. Then,
    // We can easily rewrite PHYSICAL_MEMORY_DESCRIPTOR.
    //
    MmPhysicalMemoryRange = MmGetPhysicalMemoryRanges();

    //
    // Invalid ?
    //
    if (MmPhysicalMemoryRange == NULL) return NULL;

    //
    // Compute the number of runs and the number of pages
    //
    NumberOfRuns = 0;
    NumberOfPages = 0;
    while ((MmPhysicalMemoryRange[NumberOfRuns].BaseAddress.QuadPart != 0) &&
           (MmPhysicalMemoryRange[NumberOfRuns].NumberOfBytes.QuadPart != 0))
    {
        NumberOfRuns++;
        NumberOfPages += (PFN_NUMBER)BYTES_TO_PAGES(
            MmPhysicalMemoryRange[NumberOfRuns].NumberOfBytes.QuadPart);
    }

    //
    // Invalid ?
    //
    if (NumberOfRuns == 0) return NULL;

    //
    // Compute the size of the pool to allocate and then allocate
    //
    MemoryBlockSize = sizeof(ULONG) +
        sizeof(PFN_NUMBER) +
        sizeof(PHYSICAL_MEMORY_RUN) * NumberOfRuns;

    MmPhysicalMemoryBlock = ExAllocatePoolWithTag(NonPagedPool,
                                                  MemoryBlockSize,
                                                  '  mM');

    //
    // Define PHYSICAL_MEMORY_DESCRIPTOR Header.=
    //
    MmPhysicalMemoryBlock->NumberOfRuns = NumberOfRuns;
    MmPhysicalMemoryBlock->NumberOfPages = NumberOfPages;

    for (Run = 0; Run < NumberOfRuns; Run++)
    {
        //
        // BasePage
        //
        MmPhysicalMemoryBlock->Run[Run].BasePage = 
            (PFN_NUMBER)MI_CONVERT_PHYSICAL_TO_PFN(
            MmPhysicalMemoryRange[NumberOfRuns].BaseAddress.QuadPart
            );

        //
        // PageCount
        //
        MmPhysicalMemoryBlock->Run[Run].PageCount = 
            (PFN_NUMBER)BYTES_TO_PAGES(
            MmPhysicalMemoryRange[Run].NumberOfBytes.QuadPart
            );
    }

    return MmPhysicalMemoryBlock;
}

/*++
Function Name: MiGetTotalPhysicalPages

Overview:
        - 4GB Max.

Parameters:
        - 

Return Values:
        - ULONG
--*/
ULONG
MiGetTotalPhysicalPages()
{
  SYSTEM_BASIC_INFORMATION SystemBasicInfo;
NTSTATUS NtStatus;

    //
    // We could use _PHYSICAL_MEMORY_DESCRIPTOR->NumberOfPages but MmPhysicalMemoryBlock
    // is not exported in Windows 2000. Then, we'd rather use ZwQuerySystemInformation()
    // which is supported in Windows 2000.
    //

    //
    // MmGetPhysicalMemoryRanges() uses MmPhysicalMemoryBlock to return
    // a kind of PHYSICAL_MEMORY_RUN.
    //
    /*++
    PPHYSICAL_MEMORY_RANGE
        MmGetPhysicalMemoryRanges (
            VOID
            );

        Where PHYSICAL_MEMORY_RANGE is:

        typedef struct _PHYSICAL_MEMORY_RANGE {
            PHYSICAL_ADDRESS BaseAddress;
            LARGE_INTEGER NumberOfBytes;
        } PHYSICAL_MEMORY_RANGE, *PPHYSICAL_MEMORY_RANGE;
    --*/
    NtStatus = ZwQuerySystemInformation(SystemBasicInformation, &SystemBasicInfo, sizeof(SYSTEM_BASIC_INFORMATION), 0);

    //
    // Catch error.
    //
    if (!NT_SUCCESS(NtStatus))
    {
        DbgPrint("MiGetTotalPhysicalPages()\n");
        return 0;
    }

    if (SystemBasicInfo.PhysicalPageSize != PAGE_SIZE)
    {
        DbgPrint("PhysicalPageSize (0x%08X) != 0x1000\n");
        return 0;
    }

    return SystemBasicInfo.NumberOfPhysicalPages;
}

BOOLEAN
MiX86PaeEnabled(
               )
{
ULONG RegCr4;

    RegCr4 = __readcr4();

    return (RegCr4 & CR4_PAE) ? TRUE : FALSE;
}

ULONG
MiGetPdeBase(
             )
{
ULONG DirBasePage;

    DirBasePage = __readntcr3();
    return DirBasePage;
}

NTSTATUS
IoOpenPhysicalMemory()
{

    DbgPrint("Not implemented yet.\n");

    return STATUS_SUCCESS;
}

NTSTATUS
IoClosePhysicalMemory()
{

    DbgPrint("Not implemented yet.\n");

    return STATUS_SUCCESS;
}

/*
  Gets information about the memory layout.

  - The current value of CR3 which is the kernel DTB.
  - The location of the kernel PCR block.
  - The Physical memory address ranges.

  This must be done in the context of the first CPU. See this:
  http://www.msuiche.net/2009/01/05/multi-processors-and-kdversionblock/
 */
int AddMemoryRanges(struct Win32MemroyInfo *info, int len) {
  PPHYSICAL_MEMORY_RANGE MmPhysicalMemoryRange;
  int i = 0;
  int required_length;
  ULONG CR3, KPCR;

  /* Make sure we run on the first CPU so the KPCR is valid. */

  KeSetSystemAffinityThread(1);

  _asm {
        mov eax, cr3
        mov CR3, eax

        mov eax, fs:[0x1C]          // SelfPCR
        mov KPCR, eax
       }

  info->KPCR.QuadPart = KPCR;
  info->CR3.QuadPart = __readntcr3();
  KeRevertToUserAffinityThread();

  // Enumerate address ranges.
  MmPhysicalMemoryRange = MmGetPhysicalMemoryRanges();

  if (MmPhysicalMemoryRange == NULL) {
    return -1;
  };

  /** Found out how many ranges there are. */
  for(i=0; (MmPhysicalMemoryRange[i].BaseAddress.QuadPart) &&
          (MmPhysicalMemoryRange[i].NumberOfBytes.QuadPart); i++) {
    i++;
  }

  required_length = sizeof(struct Win32MemroyInfo) +
      i * sizeof(PHYSICAL_MEMORY_RANGE);

  /* Do we have enough space? */
  if(len < required_length) {
    return -1;
  };

  info->NumberOfRuns = i;
  RtlCopyMemory(&info->Run[0], MmPhysicalMemoryRange,
                i * sizeof(PHYSICAL_MEMORY_RANGE));

  ExFreePool(MmPhysicalMemoryRange);

  return required_length;
};
