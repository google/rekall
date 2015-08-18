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

#ifndef __MacPmem__alloc__
#define __MacPmem__alloc__

////////////////////////////////////////////////////////////////////////////////
// Defines common allocation macros for both kernel and userspace
////////////////////////////////////////////////////////////////////////////////

#include <string.h>

#ifdef KERNEL
#include <libkern/OSMalloc.h>

// Used to track all allocations made with the below macros. The value is
// actually set by MacPmem.c.
extern OSMallocTag pmem_alloc_tag;

// Allocate memory of 'size', as a void pointer. Returns zeroed memory.
static inline void *PMEM_ALLOC(uint32_t size) {
    void *result = OSMalloc(size, pmem_alloc_tag);
    if (result) {
        bzero(result, size);
    }

    return result;
}

// Free memory at void *ptr of 'size' bytes in total. The 'size' must be the
// same as what was passed to create this allocation with PMEM_ALLOC.
static inline void PMEM_FREE(void *ptr, uint32_t size) {
    OSFree(ptr, size, pmem_alloc_tag);
}

#else /* ifdef KERNEL */

#include <stdlib.h>

static inline void *PMEM_ALLOC(uint32_t size) {
    void *result = malloc(size);
    if (result) {
        bzero(result, size);
    }

    return result;
}

static inline void PMEM_FREE(void *ptr, __unused uint32_t size) {
    free(ptr);
}

#endif

// Return a buffer of at least 'newsize' bytes with data from 'ptr'.
//
// This is useful because OSMalloc doesn't implement a resize operation.
//
// Arguments:
//   ptr: A buffer of size 'size' to be resized. Original buffer will be freed.
//   size: The size of 'ptr'. Must be as allocated, or you will leak memory.
//   newsize: Minimum desired size of new buffer.
//
// Returns:
//   On success, new buffer containing 'size' bytes of data from 'ptr', but
//   with at least 'newsize' bytes of allocated memory. The old buffer at
//   'ptr' may be freed during resize (just like realloc).
//
//   On error, returns 0, and leaves the old 'ptr' allocated.
static inline void *pmem_realloc(void *ptr, unsigned size, unsigned newsize) {
    if (size >= newsize) {
        return ptr;
    }

    void *newmem = PMEM_ALLOC(newsize);
    if (!newmem) {
        return 0;
    }

    memcpy(newmem, ptr, size);
    PMEM_FREE(ptr, size);

    return newmem;
}

#endif /* defined(__MacPmem__alloc__) */
