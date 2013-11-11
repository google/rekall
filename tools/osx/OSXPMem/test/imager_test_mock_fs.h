// Mock functions for testing the imager.
// The mock functions are designed to work with imager.c only, so do not include
// this in any other file or you will break things!
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

#ifndef _VOLATILITY_PMEM_IMAGER_MOCK_FS_H_
#define _VOLATILITY_PMEM_IMAGER_MOCK_FS_H_

#include <pexpert/i386/boot.h>
#include <stdint.h>
#include <sys/types.h>

// This is a list of all mocked files and is used to distinguish them in the
// mocked read/write/lseek functions. Use magic values here to recognize bugs
// more quickly that use these in real seek/read/write functions.
typedef enum {
  MEM_DEV = 0xDEADBEEF,
  DUMP_FILE = 0xFEEDFACE,
} mock_file_id_t;

// Number of segments in the test memory map.
extern const int kNumMemorySegments;
// Size of each segment in the test memory map.
extern const int kNumTestPages;

// The test memory is mock-filled with this byte.
extern const uint8_t kTestByte;

unsigned int init_mock_fs(void);
unsigned int cleanup_mock_fs(void);
unsigned int reset_mock_fs(void);

// Compare the mocked dump file with a reference file.
int validate_test_image(const char const *reference_image_path);

// Will return test values instead of actually calling the ioctl.
int mock_ioctl(int fd, unsigned long request, void *outptr);

// Manages test filehandles
int mock_open(const char *path, int flags);
// Closes test filehandles
int mock_close(int fd);
// Registers output and does sanity checks on it.
ssize_t mock_write(int fd, const void *buf, size_t nbytes);
// Reads from a buffer with test data instead of a file.
ssize_t mock_read(int fd, void *buf, size_t nbytes);
// Seeks in the test data.
off_t mock_lseek(int fd, off_t offset, int whence);

// Creates a fictional memory map for testing with the mmap functions
unsigned int init_test_mmap(uint8_t **mmap, unsigned int num_segments,
                            unsigned int desc_size, unsigned int seg_size);

#endif  // _VOLATILITY_PMEM_IMAGER_MOCK_FS_H_
