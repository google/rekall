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

#include "rangemap.h"
#include "alloc.h"
#include "logging.h"

#ifdef KERNEL
#include <kern/debug.h>  // For panic.
#endif


pmem_rangemap *pmem_rangemap_make(unsigned count) {
    if (count == 0) {
        count = PMEM_DEFAULT_RANGE_COUNT;
    }

    pmem_rangemap *rangemap = PMEM_ALLOC(sizeof(pmem_rangemap));
    if (!rangemap) {
        goto bail;
    }

    rangemap->ranges = PMEM_ALLOC(sizeof(pmem_safety_range) * count);
    if (!rangemap->ranges) {
        goto bail;
    }

    rangemap->range_count = count;
    return rangemap;

bail:
    if (rangemap) {
        pmem_rangemap_destroy(rangemap);
    }

    return 0;
}


// Grow the 'rangemap' to have capacity for at least 'count' ranges.
static int pmem_rangemap_grow(pmem_rangemap *rangemap, unsigned count) {
    pmem_safety_range *new_ranges = 0;

    if (count < rangemap->range_count) {
        goto bail;
    }

    if (count * sizeof(pmem_safety_range) < count) {
        // Overflow.
        goto bail;
    }

    new_ranges = PMEM_ALLOC(sizeof(pmem_safety_range) * count);

    if (!new_ranges) {
        goto bail;
    }

    if (!memcpy(new_ranges, rangemap->ranges,
                sizeof(pmem_safety_range) * rangemap->range_count)) {
        goto bail;
    }

    PMEM_FREE(rangemap->ranges,
              sizeof(pmem_safety_range) * rangemap->range_count);
    rangemap->ranges = new_ranges;
    rangemap->range_count = count;
    return 1;

bail:
    if (new_ranges) {
        PMEM_FREE(new_ranges, sizeof(pmem_safety_range) * count);
    }

    return 0;
}


void pmem_rangemap_destroy(pmem_rangemap *rangemap) {
    if (rangemap == 0) {
        return;
    }

    if (rangemap->ranges) {
        PMEM_FREE(rangemap->ranges,
                  rangemap->range_count * sizeof(pmem_safety_range));
    }

    PMEM_FREE(rangemap, sizeof(pmem_rangemap));
}


int pmem_rangemap_test(const pmem_rangemap *rangemap, addr64_t off) {
    if (rangemap->range_count == 0) {
        // This should not happen, as make will replace count 0 with the
        // default count of 0x10.
        return 0;
    }

    if (off > rangemap->ranges[rangemap->top_range].end) {
        return 0;
    }

    if (off < rangemap->ranges->start) {
        return 0;
    }

    unsigned bottom = 0;
    unsigned top = rangemap->top_range;
    pmem_safety_range *range = 0;

    while (bottom <= top) {
        unsigned middle = bottom + ((top - bottom) / 2);
        range = &rangemap->ranges[middle];

        if (off >= range->start && off <= range->end) {
            return range->flags;
        }

        if (off < range->start) {
            top = middle - 1;
        } else {
            bottom = middle + 1;
        }
    }

    // We should always find something because there is padding in between
    // discontiguous ranges.
    pmem_warn("Rangemap had no hits for off %#016llx. This should not happen.",
              off);

    return 0;
}


// How many ranges do we have room for in the 'rangemap'?
static inline unsigned pmem_rangemap_room(pmem_rangemap *rangemap) {
    unsigned room = rangemap->range_count - rangemap->top_range - 1;

    if (room > rangemap->range_count) {
        // Room is less than 0 and the uint wrapped around.
        pmem_fatal("Negative room in rangemap %p. This should never happen.",
                   rangemap);
#ifdef KERNEL
        panic((Negative room in rangemap. This should never happen.));
#endif
    }

    return room;
}


int pmem_rangemap_add(pmem_rangemap *rangemap, addr64_t start,
                      addr64_t end, uint32_t flags) {
    pmem_safety_range *current_range = rangemap->ranges + rangemap->top_range;

    if (current_range->end == 0) {
        // This is the first call.
        current_range->start = start;
        current_range->end = end;
        current_range->flags = flags;
        return 1;
    }

    if (start <= current_range->end) {
        // We only accept sorted, non-overlapping input.
        pmem_error("Range %#016llx - %#016llx was passed to a map out of order."
                   " Current top range is already %#016llx - %#016llx.",
                   start, end, current_range->start, current_range->end);
        return 0;
    }

    if (start == current_range->end + 1 && current_range->flags == flags) {
        // Contiguous ranges with matching flags - extend last.
        current_range->end = end;
        return 1;
    }

    if (pmem_rangemap_room(rangemap) < 2) {
        // Array full. Small arrays grow in a step, otherwise we double size.
        unsigned new_count;
        if (rangemap->range_count < 0xe) {
            new_count = 0x10;
        } else {
            new_count = rangemap->range_count * 2;
        }

        if (new_count < rangemap->range_count) {
            // Overflow.
            return 0;
        }

        if (!pmem_rangemap_grow(rangemap, new_count)) {
            // Failed to resize.
            return 0;
        }
    }

    if (start != current_range->end + 1) {
        // We add padding (range with flags 0) as an optimization, to make the
        // search function hit something faster than in log2(n) steps.
        ++rangemap->top_range;
        current_range = rangemap->ranges + rangemap->top_range;
        current_range->start = rangemap->ranges[rangemap->top_range -1].end + 1;
        current_range->end = start - 1;
        current_range->flags = 0;
    }

    ++rangemap->top_range;
    current_range = rangemap->ranges + rangemap->top_range;
    current_range->start = start;
    current_range->end = end;
    current_range->flags = flags;

    return 1;
}
