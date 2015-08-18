//  MacPmem - Rekall Memory Forensics
//  Copyright (c) 2015 Google Inc. All rights reserved.
//
//  Implements the /dev/pmem device to provide read/write access to
//  physical memory.
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
//

////////////////////////////////////////////////////////////////////////////////
// Simple rangemap for use in the kernel or userspace.
////////////////////////////////////////////////////////////////////////////////

#ifndef __MacPmem__rangemap__
#define __MacPmem__rangemap__

#ifdef KERNEL
#include <libkern/OSMalloc.h>
#include <mach/mach_types.h>
#include <libkern/libkern.h>
#else
#include <sys/types.h>
typedef unsigned long long addr64_t;
#endif

#define PMEM_MAP_READABLE 1
#define PMEM_MAP_WRITABLE 2
#define PMEM_DEFAULT_RANGE_COUNT 100

typedef struct {
    addr64_t start;
    addr64_t end;
    int flags;
} pmem_safety_range;

// Keeps track of a rangemap and related allocation metadata.
typedef struct {
    unsigned range_count; // Count of 'ranges'. It's uint32_t because OSMalloc.
    unsigned top_range; // High watermark.

    // The actual rangemap. This pointer can change when the rangemap resizes.
    pmem_safety_range *ranges;
} pmem_rangemap;


#ifdef __cplusplus
extern "C" {
#endif

// Create a new rangemap.
//
// Arguments:
//   count: Initial number of pmem_safety_range entires in the map array.
//
// Returns:
//   New rangemap struct, initialized with a container array, or nullptr on
//   failure.
pmem_rangemap *pmem_rangemap_make(unsigned count);

// Destroy (free) the rangemap.
//
// Arguments:
//   rangemap: The rangemap being freed.
void pmem_rangemap_destroy(pmem_rangemap *rangemap);

// Add a range to the map, with the appropriate 'flags'.
//
// Arguments:
//   rangemap: The rangemap being manipulated. May grow to accomodate the
//      new size.
//   start: The first offset in the range.
//   end: The last offset in the range.
//   flags: Integer flags. Any combination of PMEM_MAP_READABLE & _WRITABLE.
//
// Returns:
//   1 on success, 0 on failure.
int pmem_rangemap_add(pmem_rangemap *rangemap, addr64_t start,
                      addr64_t end, uint32_t flags);

// What are the flags for the range at offset 'off'?
//
// Arguments:
//   rangemap: The rangemap being tested.
//   off: The offset in the rangemap to be tested (starting from 0).
//
// Returns:
//   flags with PMEM_READABLE and/or PMEM_WRITABLE set.
int pmem_rangemap_test(const pmem_rangemap *rangemap, addr64_t off);

#ifdef __cplusplus
}
#endif

#endif /* defined(__MacPmem__rangemap__) */
