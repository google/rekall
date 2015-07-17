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

#ifndef MacPmem_util_h
#define MacPmem_util_h

#include <libkern/OSMalloc.h>
#include <libkern/libkern.h>
#include <mach/mach_types.h>

#ifdef __cplusplus
extern "C" {
#endif

// Used to pass context to a higher-order callback.
typedef struct {
    void *orig_callback;
    void *orig_context;
} callback_ctx_t;


// Use to signal, from callback, whether an outer loop should continue.
typedef enum {
    pmem_Continue,
    pmem_Stop
} pmem_signal_t;


// Used to track tagged buffers and their size and cursor.
// Use with pmem_alloc/pmem_resize/pmem_free.
typedef struct {
    OSMallocTag_t tag; // Tracks tag for OSMalloc.
    uint32_t size; // Tracks size for OSMalloc.
    off_t cursor; // Used for whatever nefarious purpose the caller wants.
    char *buffer; // Actual buffer.
} pmem_OSBuffer;


// Allocates a pmem_OSBuffer instance of 'size' and 'tag'.
// Returns 0 on failure.
pmem_OSBuffer *pmem_alloc(uint32_t size, OSMallocTag_t tag);

kern_return_t pmem_copy(const pmem_OSBuffer *orig,
                        pmem_OSBuffer **copy);


kern_return_t pmem_make(const char *string, uint32_t len,
                        OSMallocTag_t tag, pmem_OSBuffer **buffer);

// Resizes 'buffer' to 'size', preserving old content.
// Size must be larger than current buffer->size.
// Works by allocating a larger buffer and using memcpy. After this call,
// old buffer->buffer will be invalid memory.
// On error, returns 0 and deallocates everything, so buffer will be invalid.
kern_return_t pmem_resize(pmem_OSBuffer *buffer,
                          uint32_t size);

// Frees 'buffer', including the enclosed string pointer.
void pmem_free(pmem_OSBuffer *buffer);

#ifdef __cplusplus
}
#endif

#endif
