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

    - kd.c

Abstract:

    - 


Environment:

    - Kernel mode

Revision History:

    - Matthieu Suiche

--*/
#include "precomp.h"

PKDDEBUGGER_DATA64
KdGetDebuggerDataBlock(
                      )
{
PDBGKD_GET_VERSION64 KdVersionBlock;
PKDDEBUGGER_DATA64 DebuggerData;

    //
    // Multi Processors (MP)
    // To ensure that it's running on a specific processor.
    //
    KeSetSystemAffinityThread(1);

    //
    // __readfsdword(FIELD_OFFSET(KPCR, Prcb));
    //
    _asm
    {
        mov eax, fs:[0x1C]  // SelfPCR
        mov eax, [eax+0x34] // KdVersionBlock
        mov KdVersionBlock, eax
    }

    if (KdVersionBlock == NULL) return NULL;

    DebuggerData = (PKDDEBUGGER_DATA64)*((PULONG)KdVersionBlock->DebuggerDataList);

    //
    // Check signature and size.
    // size is always changing but not signature.
    //
    if ((DebuggerData->Header.OwnerTag != KDBG_TAG)/* && 
        (KdVersionBlock->Header.Size != sizeof(KDDEBUGGER_DATA64))*/
       )
    {
        DbgPrint("[win32dd] Error: Invalid Kernel Debugger Data block (TAG=%08X, Size=%08X).\n",
            DebuggerData->Header.OwnerTag,
            DebuggerData->Header.Size);
        //
        // TODO: Try next entry.
        //
        return NULL;
    }

    //
    // Go back to default affinity.
    //
    KeRevertToUserAffinityThread();

    return DebuggerData;
}

MY_PKPCR
__readKPCR(void)
{
MY_PKPCR KPcr;
    _asm
    {
        mov eax, fs:[0x1C]  // Self
        mov [KPcr], eax
    }
    return KPcr;
}

ULONG
__readntcr3(void)
{
ULONG DirectoryTableBase;

    DirectoryTableBase = __readKPCR()->PrcbData.ProcessorState.SpecialRegisters.Cr3;

/*
    EProcess = (PULONG)*((PULONG)KdGetDebuggerDataBlock()->PsActiveProcessHead);
    DbgPrint("PsActivePRocessHead: %08X\n", EProcess);
    (ULONG)EProcess -= 0x88;  // EPROCESS Base
    DbgPrint("NT EPROCESS: %08X\n", EProcess);
    DirectoryTableBase = EProcess[0x6];
*/

    DbgPrint("!DirectoryTableBase: %08X\n", DirectoryTableBase);

    return DirectoryTableBase;
}

USHORT 
__readcs(void)
{
USHORT SegCs;

    _asm mov word ptr [SegCs], cs

    return SegCs;
}

USHORT 
__readfs(void)
{
USHORT SegFs;

    _asm mov word ptr [SegFs], fs

    return SegFs;
}


USHORT 
__readds(void)
{
USHORT SegDs;

    _asm mov word ptr [SegDs], ds

    return SegDs;
}

USHORT 
__reades(void)
{
USHORT SegEs;

    _asm mov word ptr [SegEs], es

    return SegEs;
}

USHORT 
__readgs(void)
{
USHORT SegGs;

    _asm mov word ptr [SegGs], gs

    return SegGs;
}

USHORT 
__readss(void)
{
USHORT SegSs;

    _asm mov word ptr [SegSs], ss

    return SegSs;
}

ULONG
__readdr0(void)
{
ULONG RegDr0;

    _asm 
    {
        mov eax, dr0
        mov [RegDr0], eax
    }

    return RegDr0;
}

ULONG
__readdr1(void)
{
ULONG RegDr1;

    _asm
    {
        mov eax, dr1
        mov [RegDr1], eax
    }

    return RegDr1;
}

ULONG
__readdr2(void)
{
ULONG RegDr2;

    _asm
    {
        mov eax, dr2
        mov [RegDr2], eax
    }

    return RegDr2;
}

ULONG
__readdr3(void)
{
ULONG RegDr3;

    _asm 
    {
        mov eax, dr3
        mov [RegDr3], eax
    }

    return RegDr3;
}

ULONG
__readdr6(void)
{
ULONG RegDr6;

    _asm
    {
        mov eax, dr6
        mov [RegDr6], eax
    }

    return RegDr6;
}

ULONG
__readdr7(void)
{
ULONG RegDr7;

    _asm 
    {
        mov eax, dr7
        mov [RegDr7], eax
    }

    return RegDr7;
}

VOID
__readgdt(PDESCRIPTOR Gdtr)
{
    _asm
    {
        mov eax, [Gdtr]
        sgdt [eax]
        //
        // Multiprocessors tricks!?
        //
    }
}

VOID
__readidt(PDESCRIPTOR Idtr)
{
    _asm
    {
        mov eax, [Idtr]
        sidt [eax]
        //
        // Multiprocessors tricks!?
        //
    }
}

USHORT
__readtr(void)
{
USHORT Tr;

    _asm str [Tr]

    return Tr;
}

USHORT
__readldt(void)
{
USHORT Ldtr;

    _asm sldt [Ldtr]

    return Ldtr;
}