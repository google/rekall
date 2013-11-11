// Simple unit test framework utilizing assertions.
// A failing assertion will cause SIGABRT, which is caught to register failure.
// This allows to place assertions anywhere in the test code, even in mock
// functions, while failure will still be indicated for the specific test.
//
// Usage: utest_run("Testname", assert(testfunction(arg1, arg2, ...) == 0);
//        When finished, run utest_summary(); to get the number of failures.
//
// Notice: Failing assertions will result in a longjmp out of your code and thus
//         might leak memory. This is usually ok in a test function that failed,
//         but you should be aware of this when using large amounts of memory.
//
// Copyright 2012 Google Inc. All Rights Reserved.
// Author: Johannes Stüttgen (johannes.stuettgen@gmail.com)
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

#ifndef VOLATILITY_TOOLS_OSX_TEST_UTEST_H_
#define VOLATILITY_TOOLS_OSX_TEST_UTEST_H_

#include <assert.h>
#include <errno.h>
#include <setjmp.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

static const unsigned int kTestFailed = 1;
static const char const * kTestSuccess = "PASSED";
static const char const * kTestFailure = "FAILED";

static unsigned int current_test = 0;
static unsigned int passed_tests = 0;
static jmp_buf test_exception;

#define utest_run(test_name, test) do {                 \
    printf("[TEST %d] %s: ", current_test, test_name);  \
    signal(SIGABRT, utest_abort);                       \
    current_test++;                                     \
    if (setjmp(test_exception) != kTestFailed) {        \
      test;                                             \
      puts(kTestSuccess);                               \
      passed_tests++;                                   \
    } else {                                            \
      puts(kTestFailure);                               \
    }                                                   \
} while (0)

static void utest_abort(int signum __attribute__((unused))) {
  longjmp(test_exception, kTestFailed);
}

void utest_summary(void) {
  if (current_test == passed_tests) {
    puts("ALL TESTS PASSED");
  } else {
    printf("%d TESTS FAILED\n", current_test - passed_tests);
  }
}

#endif  // VOLATILITY_TOOLS_OSX_TEST_UTEST_H_
