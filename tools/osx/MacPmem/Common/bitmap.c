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

#include "bitmap.h"
#include "alloc.h"

pmem_bitmap *pmem_bitmap_make(uint64_t initsize_bits) {
    if (initsize_bits > PMEM_BITMAP_MAX_BIT) {
        return 0;
    }

    pmem_bitmap *bitmap = PMEM_ALLOC(sizeof(pmem_bitmap));
    if (!bitmap) {
        return 0;
    }

    // This cast is safe because we checked against PMEM_BITMAP_MAX_BIT.
    uint32_t initsize = (uint32_t)initsize_bits / 8;

    bitmap->highest_bit = 0;
    bitmap->size_bytes = initsize;
    bitmap->map = (unsigned char *)PMEM_ALLOC(initsize);

    if (!bitmap->map) {
        // Second alloc failed. Clean up and bail.
        PMEM_FREE(bitmap, sizeof(pmem_bitmap));
        return 0;
    }

    bzero(bitmap->map, initsize);
    return bitmap;
}


void pmem_bitmap_destroy(pmem_bitmap *bitmap) {
    if (bitmap == 0) {
        return;
    }

    if (bitmap->map) {
        PMEM_FREE(bitmap->map, bitmap->size_bytes);
    }

    PMEM_FREE(bitmap, sizeof(pmem_bitmap));
}


// Resize the bitmap to be at least 'newsize_bytes' in size.
//
// Returns:
//   1 on success, 0 on failure.
static int pmem_bitmap_resize(pmem_bitmap *bitmap, uint32_t newsize_bytes) {
    if (newsize_bytes < bitmap->size_bytes) {
        return 0;
    }

    if (newsize_bytes == bitmap->size_bytes) {
        return 1;
    }

    unsigned char *newmap = pmem_realloc(bitmap->map,
                                         bitmap->size_bytes,
                                         newsize_bytes);

    if (!newmap) {
        return 0;
    }

    bitmap->map = newmap;
    bitmap->size_bytes = newsize_bytes;

    return 1;
}


// Double the 'bitmap' capacity until it can accomodate the new 'highest_bit'.
//
// Returns:
//   1 on success, 0 on failure.
static int pmem_bitmap_grow(pmem_bitmap *bitmap, uint64_t highest_bit) {
    uint64_t highest_byte = highest_bit / 8 + 1;
    uint64_t required_size = bitmap->size_bytes;

    if (required_size == 0) {
        required_size = PMEM_BITMAP_DEFAULTSIZE_BYTES;
    }

    while (required_size <= highest_byte) {
        required_size *= 2;
        if (required_size < bitmap->size_bytes) {
            // Overflow.
            return 0;
        }
    }

    if (required_size > UINT32_MAX) {
        return 0;
    }

    return pmem_bitmap_resize(bitmap, (uint32_t)required_size);
}


uint64_t pmem_bitmap_set(pmem_bitmap *bitmap, uint64_t starting_bit,
                         uint64_t count) {
    uint64_t highest_bit = starting_bit + count - 1;
    if (highest_bit < starting_bit) {
        // Overflow.
        return 0;
    }

    if (!pmem_bitmap_grow(bitmap, highest_bit)) {
        return 0;
    }

    // The map is now big enough.
    uint64_t starting_byte = starting_bit / 8;
    uint64_t highest_byte = highest_bit / 8;

    if (highest_bit > bitmap->highest_bit) {
        bitmap->highest_bit = highest_bit;
    }

    if (count == 1) {
        bitmap->map[starting_byte] |= 1 << starting_bit % 8;
        return 1;
    }

    // If we're setting multiple whole bytes, the middle ones can just be
    // memset to 0xff.
    if (highest_byte > starting_byte) {
        memset(bitmap->map + starting_byte + 1, 0xff,
               highest_byte - starting_byte - 1);
    }

    if (starting_byte == highest_byte) {
        // We're only manipulating one byte, so the mask needs to fit in the
        // middle of the byte.
        unsigned diff = highest_bit % 8 - starting_bit % 8 + 1;
        unsigned mask = ((1 << diff) -1) << starting_bit % 8;
        bitmap->map[starting_byte] |= mask;
    } else {
        // We're setting first and last byte separately.
        bitmap->map[starting_byte] |= ~((1 << starting_bit % 8) - 1);

        // This is the same as 0xff >> (7 - highest_bit % 8) but the '7'
        // makes that weird.
        bitmap->map[highest_byte] |= ((1 << (highest_bit % 8 + 1)) - 1);
    }

    return count;
}

int pmem_bitmap_test(const pmem_bitmap *bitmap, uint64_t bit) {
    if (bit > bitmap->highest_bit) {
        return 0;
    }

    uint64_t byte_offset = bit / 8;
    if (byte_offset > bitmap->size_bytes) {
        // This is not necessary if we can rely on highest_bit being correct,
        // but I'd rather be safe than sorry. #defensiveprogramming
        return 0;
    }

    char byte = bitmap->map[byte_offset];
    return byte & (1 << (bit % 8));
}
