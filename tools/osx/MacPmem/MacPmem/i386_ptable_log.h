//  MacPmem - Rekall Memory Forensics
//  Copyright (c) 2015 Google Inc. All rights reserved.
//
//  Implements the /dev/pmem device to provide read/write access to
//  physical memory.
//
//  Acknowledgments:
//   PTE remapping technique based on "Anti-Forensic Resilient Memory
//   Acquisition" (http://www.dfrws.org/2013/proceedings/DFRWS2013-13.pdf)
//   and OSXPmem reference implementation by Johannes Stüttgen.
//
//  Authors:
//   Adam Sindelar (adam.sindelar@gmail.com)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef __MacPmem__i386_ptable_log__
#define __MacPmem__i386_ptable_log__

////////////////////////////////////////////////////////////////////////////////
// Implements logging of paging structures, only if compiled with DEBUG flags.
////////////////////////////////////////////////////////////////////////////////

#include <mach/mach_types.h>
#include <libkern/libkern.h>
#include "MacPmem.h"
#include "logging.h"
#include "i386_ptable.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef LOG_KERNEL_POINTERS
#define PMEM_PTE_DEBUG
#endif

#ifdef PMEM_PTE_DEBUG
void pmem_log_CR3(CR3 x, PmemLogLevel lvl, const char *reason);
void pmem_log_CR4(CR4 x, PmemLogLevel lvl, const char *reason);
void pmem_log_VIRT_ADDR(VIRT_ADDR x, PmemLogLevel lvl, const char *reason);
void pmem_log_PML4E(PML4E x, PmemLogLevel lvl, const char *reason);
void pmem_log_PDPTE(PDPTE x, PmemLogLevel lvl, const char *reason);
void pmem_log_PDE(PDE x, PmemLogLevel lvl, const char *reason);
void pmem_log_PTE(PTE x, PmemLogLevel lvl, const char *reason);

#else

#define pmem_log_CR3(x, lvl, reason)
#define pmem_log_CR4(x, lvl, reason);
#define pmem_log_VIRT_ADDR(x, lvl, reason);
#define pmem_log_PML4E(x, lvl, reason);
#define pmem_log_PDPTE(x, lvl, reason);
#define pmem_log_PDE(x, lvl, reason);
#define pmem_log_PTE(x, lvl, reason);

#endif

#ifdef __cplusplus
}
#endif
#endif
