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

#ifndef __MacPmem__tests__
#define __MacPmem__tests__

// A test has a name and a function pointer.
typedef int (*test_func_t)(void);
typedef struct {
    const char name[40];
    const test_func_t call;

    unsigned flags;
} test_t;

#define TEST_REQUIRE_KEXT 1
#define TEST_REQUIRE_WRITE 2

////////////////////////////////////////////////////////////////////////////////
// MARK: Driver tests
////////////////////////////////////////////////////////////////////////////////
int test_contention();
int test_unload_with_open();
int test_phys_read();
int test_info_read();
int test_sysctl();
int test_kextload_stress();
int test_invalid_reads();
int test_symbols();
int test_rangemap_real();


////////////////////////////////////////////////////////////////////////////////
// MARK: Tests that don't require the driver
////////////////////////////////////////////////////////////////////////////////
int test_rangemap();
int test_rangemap_nonsequential();

// Table of all the tests we'll run.
static const test_t tests[] = {
    // Driver tests:
    {"test_sysctl", &test_sysctl, TEST_REQUIRE_KEXT},
    {"test_phys_read", &test_phys_read, TEST_REQUIRE_KEXT},
    {"test_info_read", &test_info_read, TEST_REQUIRE_KEXT},
    {"test_contention", &test_contention, TEST_REQUIRE_KEXT},
    {"test_unload_with_open", &test_unload_with_open, TEST_REQUIRE_KEXT},
    {"test_invalid_reads", &test_invalid_reads, TEST_REQUIRE_KEXT},
    {"test_kextload_stress", &test_kextload_stress, TEST_REQUIRE_KEXT},
    {"test_symbols", &test_symbols, TEST_REQUIRE_KEXT},

    // Tests with no driver:
    {"test_rangemap", &test_rangemap, 0},
    {"test_rangemap_nonsequential", &test_rangemap_nonsequential, 0},
    {"test_rangemap_real", &test_rangemap_real, 0},
};

#endif /* defined(__MacPmem__tests__) */
