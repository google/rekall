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
#include "bitmap.h"
#include "logging.h"


// Verifies that all the expected bits are set in the map.
//
// Arguments:
//   b: The bitmap.
//   expected_bits: Pointer to the first expected bit's offset. This array
//      must be sorted.
//   count_bits: Size of 'expected_bits'.
//
// Returns:
//   Index of the first invalid bit in the bitmap. If none are found, returns 0.
static uint64_t verify_map(pmem_bitmap *b, uint64_t *expected_bits,
                           unsigned count_bits) {
    uint64_t *next_expected = expected_bits;
    uint64_t max_bit = b->size_bytes * 8 + 8;
    for (uint64_t bit = 0; bit <= max_bit; ++bit) {
        int res = pmem_bitmap_test(b, bit);

        if (bit == *next_expected) {
            if (!res) {
                pmem_error("Bit %llu should be set.", bit);
                return bit;
            }

            if (expected_bits + count_bits -1 > next_expected) {
                ++next_expected;
            }
        } else if (res) {
            pmem_error("Bit %llu should not be set.", bit);
            return bit;
        }
    }

    return 0;
}


// Test basic bitmap behavior.
int test_bitmap() {
    pmem_bitmap *b = pmem_bitmap_make(1); // Forcing growth.

    if (b->highest_bit != 0) {
        return -1;
    }

    pmem_bitmap_set(b, 19, 1);
    pmem_bitmap_set(b, 60, 1);

    uint64_t expected_bits[] = {19, 60};
    if (verify_map(b, expected_bits, 2) != 0) {
        return -2;
    }

    pmem_bitmap_destroy(b);
    return 0;
}


// Test filling the bitmap out of sequence.
int test_bitmap_nonsequential() {
    pmem_bitmap *b = pmem_bitmap_make(0);

    pmem_bitmap_set(b, 60, 1);
    pmem_bitmap_set(b, 19, 1);

    uint64_t expected_bits[] = {19, 60};
    if (verify_map(b, expected_bits, 2) != 0) {
        return -1;
    }

    pmem_bitmap_destroy(b);
    return 0;
}


// Test setting ranges of bits.
int test_bitmap_range() {
    pmem_bitmap *b = pmem_bitmap_make(0x100);

    // Simple case: all in one byte.
    pmem_bitmap_set(b, 2, 4);
    uint64_t expected_bits[] = {2, 3, 4, 5};
    if (verify_map(b, expected_bits, 4)) {
        return -1;
    }

    // Now set stuff across byte boundaries.
    pmem_bitmap_set(b, 14, 12);
    pmem_bitmap_set(b, 100, 1);
    uint64_t expected_bits2[] = {
        2, 3, 4, 5, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 100
    };
    if (verify_map(b, expected_bits2, 17)) {
        return -2;
    }

    // High and low byte with no middle.
    pmem_bitmap_set(b, 30, 5);
    uint64_t expected_bits3[] = {
        2, 3, 4, 5, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        30, 31, 32, 33, 34,
        100
    };
    if (verify_map(b, expected_bits3, 22)) {
        return -2;
    }

    pmem_bitmap_destroy(b);
    return 0;
}


// Setting a crazy high bit should work - test resizing.
int test_bitmap_high_bit() {
    pmem_bitmap *b = pmem_bitmap_make(0x10);

    // Page-aligned values often catch off-by-one errors.
    pmem_bitmap_set(b, 0x400000, 1);
    uint64_t expected_bits[] = {0x400000};
    if (verify_map(b, expected_bits, 1) != 0) {
        return -1;
    }

    pmem_bitmap_destroy(b);
    return 0;
}
