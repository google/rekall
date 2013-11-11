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

#include "error_log.h"
#include "imager_test_mock_fs.h"
#include "utest.h"

#include "../imager/imager.h"

// These paths are relative from the directory of the makefile.
static const char const *kRawTestImagePath = "test/test_image_raw.dump";
static const char const *kElfTestImagePath = "test/test_image_elf.dump";
static const char const *kMachTestImagePath = "test/test_image_mach.dump";

unsigned int init_tests(void) {
  unsigned int status = EXIT_FAILURE;

  // Restrict the imagers logging to error messages to avoid cluttering the
  // testing output.
  loglevel = ERR;
  if (init_mock_fs() == EXIT_FAILURE) {
    ERROR_LOG("Failed to initialize the mock filesystem");
    goto error;
  }
  status = EXIT_SUCCESS;
error:
  return status;
}

unsigned int cleanup_tests(void) {
  unsigned int status = EXIT_FAILURE;

  if (cleanup_mock_fs() == EXIT_FAILURE) {
    ERROR_LOG("Failed to cleanup mock filesystem");
    goto error;
  }
  status = EXIT_SUCCESS;
error:
  return status;
}

// Test if the get_mmap() function correctly uses the ioctls to obtain the
// memory map and its meta data.
void test_get_mmap(void) {
  uint8_t *mmap = NULL;
  uint8_t *test_mmap = NULL;
  unsigned int mmap_size = 0;
  unsigned int mmap_desc_size = 0;

  assert(init_test_mmap(&test_mmap, kNumMemorySegments,
                        sizeof(EfiMemoryRange), kNumTestPages) == EXIT_SUCCESS);
  assert(test_mmap != NULL);
  assert(get_mmap(&mmap, &mmap_size, &mmap_desc_size, MEM_DEV) == EXIT_SUCCESS);
  assert(mmap_size == kNumMemorySegments * sizeof(EfiMemoryRange));
  assert(mmap_desc_size == sizeof(EfiMemoryRange));
  assert(mmap != NULL);
  assert(memcmp(mmap, test_mmap, mmap_size) == 0);
  // Don't forget cleaning up
  free(mmap);
  free(test_mmap);
}

// End to end test of the raw imaging functions, using a mocked
// filesystem.
void test_dump_memory_raw(void) {
  assert(reset_mock_fs() == EXIT_SUCCESS);
  assert(dump_memory_raw(MEM_DEV, DUMP_FILE) == EXIT_SUCCESS);
  assert(validate_test_image(kRawTestImagePath) == 0);
}

// End to end test of the elf imaging functions, using a mocked
// filesystem.
void test_dump_memory_elf(void) {
  assert(reset_mock_fs() == EXIT_SUCCESS);
  assert(dump_memory_elf(MEM_DEV, DUMP_FILE) == EXIT_SUCCESS);
  assert(validate_test_image(kElfTestImagePath) == 0);
}

// End to end test of the mach-o imaging functions, using a mocked
// filesystem.
void test_dump_memory_macho(void) {
  assert(reset_mock_fs() == EXIT_SUCCESS);
  assert(dump_memory_macho(MEM_DEV, DUMP_FILE) == EXIT_SUCCESS);
  assert(validate_test_image(kMachTestImagePath) == 0);
}

int main(int argc, char **argv) {
  int status = EXIT_FAILURE;

  if (init_tests() == EXIT_FAILURE) {
    ERROR_LOG("Failed to initialize imager tests");
    goto error;
  }
  utest_run("getting the memory map", test_get_mmap());
  utest_run("creating a raw image", test_dump_memory_raw());
  utest_run("creating an elf image", test_dump_memory_elf());
  utest_run("creating a mach-o image", test_dump_memory_macho());
  utest_summary();
  if (cleanup_tests() == EXIT_FAILURE) {
    ERROR_LOG("Failed to release test resources");
    goto error;
  }
  status = EXIT_SUCCESS;
error:
  return status;
}
