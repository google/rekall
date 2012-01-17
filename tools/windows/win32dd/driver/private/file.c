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

    - file.c

Abstract:

    - 


Environment:

    - Kernel mode

Revision History:

    - Matthieu Suiche

--*/

#include "precomp.h"

NTSTATUS
wddCreateFile(IN PUNICODE_STRING FullDosPath,
              OUT PHANDLE Handle)
{
OBJECT_ATTRIBUTES ObjAttributes;
IO_STATUS_BLOCK IoStatusBlock;
NTSTATUS NtStatus;

    //
    // We initialize object attributes of file
    //
    InitializeObjectAttributes(&ObjAttributes,
                               FullDosPath,
                               OBJ_KERNEL_HANDLE,
                               (HANDLE) NULL,
                               (PSECURITY_DESCRIPTOR) NULL);

    //
    // We create the output file. We copy all pages into this file.
    //
    NtStatus = ZwCreateFile(Handle,
                            FILE_WRITE_ACCESS | SYNCHRONIZE,
                            &ObjAttributes,
                            &IoStatusBlock,
                            NULL,
                            FILE_ATTRIBUTE_NORMAL,
                            0,
                            FILE_SUPERSEDE,
                            FILE_SEQUENTIAL_ONLY | FILE_SYNCHRONOUS_IO_NONALERT,
                            NULL,
                            0);

    //
    // We catch error if we cannot create the file.
    //
    if (!NT_SUCCESS(NtStatus))
    {
        DbgPrint("[win32dd] Error: ZwCreateFile(dump) => %08X\n", NtStatus);
        *Handle = INVALID_HANDLE;
    }
    
    return NtStatus;
}

NTSTATUS
wddCloseFile(IN HANDLE Handle
             )
{
    //
    // Closing file handle.
    //
    return ZwClose(Handle);
}