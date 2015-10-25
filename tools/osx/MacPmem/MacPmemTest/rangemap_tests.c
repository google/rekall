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

#include "tests.h"
#include "rangemap.h"
#include "logging.h"

int assert_rangemap_test(pmem_rangemap *r, addr64_t offset, int flags) {
    int actual = pmem_rangemap_test(r, offset);
    if (actual == flags) {
        return 1;
    }

    pmem_error("Offset %#016llx in map %p was expected to be %d, but was %d.",
               offset, r, flags, actual);
    return 0;
}


// Test basic rangemap behavior.
int test_rangemap() {
    pmem_rangemap *r = pmem_rangemap_make(1); // Force growth.

    if (r->top_range != 0) {
        return -1;
    }

    if (!pmem_rangemap_add(r, 0, 0x1000, PMEM_MAP_READABLE)) {
        pmem_error("Could not add first range.");
        return -1;
    }

    if (!pmem_rangemap_add(r, 0x2001, 0x3000,
                           PMEM_MAP_WRITABLE | PMEM_MAP_READABLE)) {
        pmem_error("Could not add second range.");
        return  -2;
    }

    if (!assert_rangemap_test(r, 0x500, PMEM_MAP_READABLE)) {
        return -3;
    }

    if (!assert_rangemap_test(r, 0x1500, 0)) {
        return -4;
    }

    if (!assert_rangemap_test(r, 0x2500,
                              PMEM_MAP_READABLE | PMEM_MAP_WRITABLE)) {
        return -5;
    }

    pmem_rangemap_destroy(r);
    return 0;
}


// Test filling the rangemap out of sequence.
int test_rangemap_nonsequential() {
    // Disable error logging because we cause them on purpose.
    PmemLogLevel previous_level = pmem_logging_level;
    pmem_logging_level = kPmemFatal;
    pmem_rangemap *r = pmem_rangemap_make(0x100);

    // Starting the map past zero should work.
    if (!pmem_rangemap_add(r, 0x1001, 0x2000, 1)) {
        return -1;
    }

    // Out of sequence ranges should not work.
    if (pmem_rangemap_add(r, 0x500, 0x1000, 2)) {
        return -2;
    }

    // Overlapping, even by one byte, should fail too.
    if (pmem_rangemap_add(r, 0x2000, 0x3000, 1)) {
        return -3;
    }

    pmem_logging_level = previous_level;
    return 0;
}
