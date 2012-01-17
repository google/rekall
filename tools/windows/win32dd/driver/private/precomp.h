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

    - precomp.h

Abstract:

    - 


Environment:

    - Kernel mode

Revision History:

    - Matthieu Suiche

--*/

//
// DDK Includes
//

//#include <ntddk.h>
#include <ntifs.h>
#include <wdmsec.h>
#include <initguid.h>
#include <stdarg.h>
#include <stdio.h>

//
// Local includes
//
#include "win32dd.h"
#include "io.h"
#include "crashdmp.h"
#include "mm.h"
#include "ke.h"
#include "kd.h"
#include "zwddk.h"
#include "file.h"

#define LOBYTE(w) ((UCHAR)(((UCHAR)(w)) & 0xff))
#define HIBYTE(w) ((UCHAR)((ULONG)(w) >> 8))

#define ZERO_ADDR(addr) { \
    addr.LowPart = (ULONG) 0; \
    addr.HighPart = (ULONG) 0; \
    }

#define NULL_TAG 'nooM'

#define KDBG_TAG 'GBDK'

#define INVALID_HANDLE 0

DEFINE_GUID(GUID_DEVCLASS_WIN32DD_DUMPER, 
            0x7474614dL, 
            0x6968, 
            0x7565, 
            0x53, 0x75, 0x69, 0x63, 0x68, 0x65, 0x3c, 0x33);
