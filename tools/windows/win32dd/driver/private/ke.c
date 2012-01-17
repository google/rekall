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

    - ke.c

Author:

    Matthieu Suiche (msuiche) 4-jan-2009

Abstract:

Environment:

    - Kernel mode

Revision History:

    - Matthieu Suiche

--*/

#include "precomp.h"


/*++
Function Name: xxxKeQueryActiveProcessorCount

Overview:
        - The xxxKeQueryActiveProcessorCount function returns the number of
          currently active processors.

Parameters:
        - 

Return Values:
        - UCHAR
--*/
UCHAR
xxxKeQueryActiveProcessorCount(
                              )
{
KAFFINITY ActiveProcessors;

//
// When Microsoft O.S. will support more than 256 processors, 
// I'd have to modify this definition :-).
//
UCHAR NumberProcessors;

ULONG ProcessorMask;

    ActiveProcessors = KeQueryActiveProcessors();

    NumberProcessors = 0;

    //DbgPrint("ActiveProcessors: %d\n", ActiveProcessors);

    //
    // Active processors are encoded into a 32bits values.
    // 32 bits processors limitation had been raised only since Windows Seven.
    //
    for (ProcessorMask = 0; ProcessorMask < MAXIMUM_PROC_PER_SYSTEM; ProcessorMask += 1)
    {
        if ((ActiveProcessors >> ProcessorMask) & 1) NumberProcessors += 1;
    }

    //DbgPrint("NumberProcessors: %d\n", NumberProcessors);

    return NumberProcessors;
}

/*++
Function Name: KeProcessorArchitecture

Overview:
        - 

Parameters:
        - 

Return Values:
        - USHORT
--*/
USHORT
KeQueryProcessorArchitecture(
                             )
{
SYSTEM_PROCESSOR_INFORMATION ProcessorInfo;
NTSTATUS NtStatus;

    NtStatus = ZwQuerySystemInformation(SystemProcessorInformation, &ProcessorInfo, sizeof(SYSTEM_PROCESSOR_INFORMATION), 0);

    if (!NT_SUCCESS(NtStatus))
    {
        DbgPrint("KeQueryProcessorArchitecture()\n");
        return 0;
    }

    return ProcessorInfo.KeProcessorArchitecture;
}

VOID
KeSaveStateForHibernate(OUT PKPROCESSOR_STATE32 ProcState
                          )
{
    //
    // Context
    //
    xxxRtlCaptureContext(&ProcState->ContextFrame);

    //
    // Processor.
    //
    xxxKiSaveProcessorControlState(ProcState);
}

VOID
xxxRtlCaptureContext(OUT PCONTEXT Context
                    )
{
USHORT SegCs, SegFs, SegDs, SegEs, SegGs, SegSs;

    Context->Eax = 'TTAM';
    Context->Ecx = 'TTAM';
    Context->Ebx = 'TTAM';
    Context->Edx = 'TTAM';

    Context->Esi = 'TTAM';
    Context->Edi = 'TTAM';

    Context->SegCs = __readcs();
    Context->SegFs = __readfs();
    Context->SegDs = __readds();
    Context->SegEs = __reades();
    Context->SegGs = __readgs();
    Context->SegSs = __readss();

    Context->Eip = (ULONG)&KeSaveStateForHibernate;
    Context->Ebp = 'TTAM';
    Context->Esp = 'TTAM';
}

VOID
xxxKiSaveProcessorControlState(OUT PKPROCESSOR_STATE32 ProcState
                               )
{
    ProcState->SpecialRegisters.Cr0 = __readcr0();
    ProcState->SpecialRegisters.Cr2 = __readcr2();
    ProcState->SpecialRegisters.Cr3 = __readntcr3();
    DbgPrint("ProcState->SpecialRegisters.Cr3: %08X\n", 
        ProcState->SpecialRegisters.Cr3);
    //
    // Unlike the original MSFT code, we don't check KeFeatureBits,
    // we save Cr4 anyway.
    //
    ProcState->SpecialRegisters.Cr4 = __readcr4();


    //
    // Debug registers
    //
    ProcState->ContextFrame.Dr0 = __readdr0();
    ProcState->ContextFrame.Dr1 = __readdr1();
    ProcState->ContextFrame.Dr2 = __readdr2();
    ProcState->ContextFrame.Dr3 = __readdr3();
    ProcState->ContextFrame.Dr6 = __readdr6();
    ProcState->ContextFrame.Dr7 = __readdr7();

    //
    // IDT, GDT, ..
    //
    ProcState->SpecialRegisters.Tr = __readtr();
    ProcState->SpecialRegisters.Ldtr = __readldt();

    __readidt(&ProcState->SpecialRegisters.Idtr);
    __readgdt(&ProcState->SpecialRegisters.Gdtr);
}

VOID
FASTCALL
KeDisableInterrupts(
                    )
{
    _asm cli
}

VOID
FASTCALL
KeRestoreInterrupts(
                    )
{
    _asm sti
}

VOID
FASTCALL
KiFlushSingleTb(IN PVOID Va
               )
{
    //
    // Fast call
    //
    _asm invlpg [ecx]
}

