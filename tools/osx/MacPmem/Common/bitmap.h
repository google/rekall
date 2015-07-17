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
// Simple bitmap for use in the kernel or userspace.
////////////////////////////////////////////////////////////////////////////////

#ifndef __MacPmem__bitmap__
#define __MacPmem__bitmap__

#ifdef KERNEL
#include <libkern/OSMalloc.h>
#include <mach/mach_types.h>
#include <libkern/libkern.h>
#else
#include <sys/types.h>
#endif

#define PMEM_BITMAP_MAX_BIT (UINT32_MAX * 8)
#define PMEM_BITMAP_DEFAULTSIZE_BYTES 0x10

// Keeps track of a bitmap and related allocation metadata.
typedef struct {
    uint32_t size_bytes; // Size of map. It's uint32_t because of OSMalloc.
    uint64_t highest_bit; // High watermark in bits.

    // The actual bitmap. This pointer can change when the bitmap resizes.
    unsigned char *map;
} pmem_bitmap;


#ifdef __cplusplus
extern "C" {
#endif

// Create a new bitmap.
//
// Arguments:
//   initsize_bits: Initial size of the bitmap, in bits. At most
//   PMEM_BITMAP_MAX_BIT.
//
// Returns:
//   New bitmap struct, initialized to initsize, or nullptr on failure.
pmem_bitmap *pmem_bitmap_make(uint64_t initsize_bits);

// Destroy (free) the bitmap.
//
// Arguments:
//   bitmap: The bitmap being freed.
void pmem_bitmap_destroy(pmem_bitmap *bitmap);

// Set a range of bits in the bitmap to 1.
//
// Arguments:
//   bitmap: The bitmap being manipulated. May grow to accomodate the new size.
//   starting_bit: The first bit to set (bits are indexed from 0).
//   count: How many bits should be set in total, starting with 'starting_bit'.
//
// Returns:
//   Number of bits set. If this is different than 'count' an error occurred.
uint64_t pmem_bitmap_set(pmem_bitmap *bitmap, uint64_t starting_bit,
                         uint64_t count);

// Is the 'bit' set in 'bitmap'?
//
// Arguments:
//   bitmap: The bitmap being tested.
//   bit: The offset of the bit in the bitmap to be tested (starting from 0).
//
// Returns:
//   1 if the bit is set, otherwise 0.
int pmem_bitmap_test(const pmem_bitmap *bitmap, uint64_t bit);

#ifdef __cplusplus
}
#endif

#endif /* defined(__MacPmem__bitmap__) */
