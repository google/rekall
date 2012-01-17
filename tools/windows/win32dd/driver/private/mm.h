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

    - mm.h

Abstract:

    - 


Environment:

    - Kernel mode

Revision History:

    - Matthieu Suiche

--*/

//
//
//

#ifndef _MI_H_
#define _MI_H_

#define MI_CONVERT_PHYSICAL_TO_PFN(Pa) ((Pa << 3) >> 15)

typedef struct _PHYSICAL_MEMORY_RUN {
    PFN_NUMBER BasePage;
    PFN_NUMBER PageCount;
} PHYSICAL_MEMORY_RUN, *PPHYSICAL_MEMORY_RUN;

typedef struct _PHYSICAL_MEMORY_DESCRIPTOR {
    ULONG NumberOfRuns;
    PFN_NUMBER NumberOfPages;
    PHYSICAL_MEMORY_RUN Run[1]; // NumberOfRuns is the total entries.
} PHYSICAL_MEMORY_DESCRIPTOR, *PPHYSICAL_MEMORY_DESCRIPTOR;

typedef struct _MMPTE_HARDWARE {
    ULONG64 Valid:1;
    ULONG64 Write:1;
    ULONG64 Owner:1;
    ULONG64 WriteThrough:1;
    ULONG64 CacheDisable:1;
    ULONG64 Accessed:1;
    ULONG64 Dirty:1;
    ULONG64 LargePage:1;
    ULONG64 Global:1;
    ULONG64 CopyOnWrite:1;
    ULONG64 Prototype:1;
    ULONG64 reserved0:1;
    ULONG64 PageFrameNumber:28;
    ULONG64 reserved1:12;
    ULONG64 SoftwareWsIndex:11;
    ULONG64 NoExecute:1;
} MMPTE_HARDWARE, *PMMPTE_HARDWARE, MMPTE, *PMMPTE;

//
// Functions
//
ULONG
MiGetTotalPhysicalPages(
);

BOOLEAN
MiX86PaeEnabled(
);

ULONG
MiGetPdeBase(
);

PMMPTE
MiGetPteAddress(
    ULONG Va
);

PVOID
MmMapInCrashSpace(
    PHYSICAL_ADDRESS PhysicalAddress,
    ULONG NumberOfBytes
);

VOID
MmReleaseCrashSpace(
    IN ULONG NumberOfBytes
);

PPHYSICAL_MEMORY_DESCRIPTOR
MmGetPhysicalMemoryBlock(
    VOID
);
//
//
//
/*
#define PTE_BASE ((ULONG)0xC0000000)
#define MiGetPteAddress(va) ((PMMPTE)(((((ULONG)(va)) >> 12) << 2) + PTE_BASE))
//
// Works only with Windows 2003 and below. Since Windows Vista, developpers choosed to used 
// MiReserveSystemPtes API instead of an fixed virtual address.
//
#define MM_CRASH_DUMP_VA ((PVOID)(0xFFBE0000))

PMMPTE MmCrashDumpPte = (MiGetPteAddress(MM_CRASH_DUMP_VA));

#define MiGetVirtualAddressMappedByPte(PTE) ((PVOID)((ULONG)(PTE) << 10))
*/
#define MMDBG 0

#endif