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

    - io.h

Abstract:

    - 


Environment:

    - Kernel mode

Revision History:

    - Matthieu Suiche

--*/

#ifndef _IO_H_
#define _IO_H_

//
// System Information Classes.
//

NTSTATUS 
IoWriteRawDump_Level0 (
    IN PDEVICE_OBJECT DeviceObject, 
    IN PUNICODE_STRING FilePath
);

NTSTATUS 
IoWriteRawDump_Level1 (
    IN PDEVICE_OBJECT DeviceObject, 
    IN PUNICODE_STRING FilePath
);


NTSTATUS
IoWriteCrashDump(
    IN PUNICODE_STRING FullDosPath,
    IN ULONG BugCheckCode,
    IN ULONG_PTR BugCheckParameter1,
    IN ULONG_PTR BugCheckParameter2,
    IN ULONG_PTR BugCheckParameter3,
    IN ULONG_PTR BugCheckParameter4,
    IN PCONTEXT Context
);
#endif