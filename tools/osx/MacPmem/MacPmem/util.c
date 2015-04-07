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

#include "util.h"

// Allocates a pmem_OSBuffer instance of 'size' and 'tag'.
// Returns 0 on failure.
pmem_OSBuffer *pmem_alloc(uint32_t size, OSMallocTag_t tag) {
    pmem_OSBuffer *buffer = (pmem_OSBuffer *)OSMalloc(sizeof(pmem_OSBuffer),
                                                      tag);
    if (!buffer) {
        goto error;
    }

    bzero(buffer, sizeof(pmem_OSBuffer));
    buffer->size = size;
    buffer->tag = tag;
    buffer->buffer = (char *)OSMalloc(size, tag);

    if (!buffer->buffer) {
        goto error;
    }

    bzero(buffer->buffer, buffer->size);

    return buffer;

error:
    if (buffer) {
        OSFree(buffer, sizeof(pmem_OSBuffer), tag);
    }

    return 0;
}


kern_return_t pmem_copy(const pmem_OSBuffer *orig, pmem_OSBuffer **copy) {
    *copy = pmem_alloc(orig->size, orig->tag);
    if (*copy == 0) {
        printf("ARGH?\n\n");
        return KERN_FAILURE;
    }

    strncpy((*copy)->buffer, orig->buffer, orig->size);
    return KERN_SUCCESS;
}


kern_return_t pmem_make(const char *string, uint32_t len,
                        OSMallocTag_t tag, pmem_OSBuffer **buffer) {
    *buffer = pmem_alloc(len, tag);
    if (*buffer == 0) {
        return KERN_FAILURE;
    }

    strncpy((*buffer)->buffer, string, len);

    return KERN_SUCCESS;
}


// Resizes 'buffer' to 'size', preserving old content.
// Size must be larger than current buffer->size.
// Works by allocating a larger buffer and using memcpy. After this call,
// old buffer->buffer will be invalid memory.
// On error, returns 0 and deallocates everything, so buffer will be invalid.
kern_return_t pmem_resize(pmem_OSBuffer *buffer, uint32_t size) {
    char *newbuf = 0;
    if (!buffer) {
        goto error;
    }

    if (size < buffer->size) {
        // We're already bigger. That's fine - nothing to do.
        return KERN_SUCCESS;
    }

    newbuf = (char *)OSMalloc(size, buffer->tag);
    if (!newbuf) {
        goto error;
    }
    bzero(newbuf, size);

    memcpy(newbuf, buffer->buffer, buffer->size);
    OSFree(buffer->buffer, buffer->size, buffer->tag);
    buffer->buffer = newbuf;
    buffer->size = size;

    return KERN_SUCCESS;

error:
    if (newbuf) {
        OSFree(newbuf, size, buffer->tag);
    }

    if (buffer) {
        if (buffer->buffer) {
            OSFree(buffer->buffer, buffer->size, buffer->tag);
        }
        OSFree(buffer, sizeof(pmem_OSBuffer), buffer->tag);
    }

    return KERN_FAILURE;
}

// Frees 'buffer', including the enclosed string pointer.
void pmem_free(pmem_OSBuffer *buffer) {
    if (!buffer) {
        return;
    }

    if (buffer->buffer) {
        OSFree(buffer->buffer, buffer->size, buffer->tag);
    }

    OSFree(buffer, sizeof(pmem_OSBuffer), buffer->tag);
}
