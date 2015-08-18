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

#ifndef __MacPmem__safety__
#define __MacPmem__safety__

////////////////////////////////////////////////////////////////////////////////
// Implements a page-level read/write safety based on EFI physmap ranges.
////////////////////////////////////////////////////////////////////////////////

#include <mach/mach_types.h>
#include <libkern/libkern.h>
#include "rangemap.h"


// The init function bellow will initialize this rangemap to hold the readable
// ranges in memory, with page-level resolution, as reported by the EFI physmap.
//
// The r/w handler to physical memory can use this rangemap to decide whether
// an IO operation to a certain page should be permitted.
extern pmem_rangemap *safety_rangemap;

// Initializes the safety_rangemap.
//
// Uses the meta EFI enumeration code from meta.cpp.
//
// Returns:
//   KERN_SUCCESS if everything works, otherwise KERN_FAILURE, which usually
//   means the meta subsystem failed to get data.
kern_return_t pmem_safety_init(void);

// Tears down the safety rangemap.
//
// Returns:
//   Not a thing.
void pmem_safety_cleanup(void);

#endif /* defined(__MacPmem__safety__) */
