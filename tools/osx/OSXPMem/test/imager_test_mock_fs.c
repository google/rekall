// Mock file system to test imager.c
// Uses test values instead of real memory and redirects writes to a temp file.
// Also simulates ioctls to enable memory map simulation.
//
// Must be initialized with init_mock_fs() before use. Use cleanup_mock_fs() to
// release resources.
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
// Will return test values instead of actually calling the ioctl.

#include "imager_test_mock_fs.h"

#include "error_log.h"

#include "../imager/imager.h"
#include "../pmem/pmem_ioctls.h"

#include <fcntl.h>
#include <limits.h>
#include <mach/vm_param.h>
#include <pexpert/i386/boot.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <unistd.h>

// Number of segments in the test memory map.
const int kNumMemorySegments = 15;
// Size of each segment in the test memory map.
const int kNumTestPages = 128;

// The test memory is a sequence of this byte.
const uint8_t kTestByte = 0xFF;

// A temporary file that can be used to write test images.
int temp_file = -1;
char temp_file_name[] = "/tmp/test_image_XXXXXX";

// Initialize global data structures, create temp files.
unsigned int init_mock_fs(void) {
  unsigned int status = EXIT_FAILURE;
  temp_file = mkstemp(temp_file_name);
  if (temp_file == -1) {
    ERROR_LOG("Failed to create temp file");
    goto error;
  }
  /*
  if (tmpnam(temp_file_name) == NULL) {
    ERROR_LOG("Unable to create temp file name");
    goto error;
  }
  temp_file = open(temp_file_name, O_RDWR | O_CREAT | O_TRUNC, 0600);
  if (temp_file == -1) {
    ERROR_LOG("Unable to create temp file");
    goto error;
  }
  */
  if (lseek(temp_file, 0, SEEK_SET) != 0) {
    ERROR_LOG("Failed to seek to beginning of temp file");
  }
  status = EXIT_SUCCESS;
error:
  return status;
}

// Cleanup global data structures, delete temp files.
unsigned int cleanup_mock_fs(void) {
  unsigned int status = EXIT_FAILURE;

  if (close(temp_file) == -1) {
    ERROR_LOG("Failed to close temp file");
    goto error;
  }
  if (remove(temp_file_name) != 0) {
    ERROR_LOG("Failed to delete the temp file");
    goto error;
  }
  status = EXIT_SUCCESS;
error:
  return status;
}

// Re-initialize mock file-system.
unsigned int reset_mock_fs(void) {
  unsigned int status = EXIT_FAILURE;

  if (cleanup_mock_fs() == EXIT_FAILURE) {
    ERROR_LOG("Failed to clean mock fs");
    goto error;
  }
  if (init_mock_fs() == EXIT_FAILURE) {
    ERROR_LOG("Failed to re-initialize mock fs");
    goto error;
  }
  status = EXIT_SUCCESS;
error:
  return status;
}

// Compares two binary files using read() and memcmp().
//
// args: open file descriptors for the two files to compare.
//
// return: If the files are equal 0.
//         If the size differs the difference.
//         In any other case -1.
//
int filecmp(int file1, int file2) {
  struct stat stat_buf;
  off_t size1, size2;
  uint8_t buf1[PAGE_SIZE];
  uint8_t buf2[PAGE_SIZE];
  int equal = -1;

  if (fstat(file1, &stat_buf) != 0) {
    ERROR_LOG("Failed to get stat for file 1");
    goto end;
  }
  size1 = stat_buf.st_size;
  if (fstat(file2, &stat_buf) != 0) {
    ERROR_LOG("Failed to get stat for file 2");
    goto end;
  }
  // Compare sizes first
  size2 = stat_buf.st_size;
  if (size1 != size2) {
    equal = size1 - size2;
    goto end;
  }
  for (off_t chunk = 0; chunk < size1 / PAGE_SIZE; chunk++) {
    if (lseek(file1, chunk * PAGE_SIZE, SEEK_SET) == -1) {
      ERROR_LOG("Failed to seek to chunk %lld in file 1", chunk);
      goto end;
    }
    if (read(file1, &buf1, PAGE_SIZE) == -1) {
      ERROR_LOG("Failed to read page %lld from file 1 while comparing", chunk);
      goto end;
    }
    if (lseek(file1, chunk * PAGE_SIZE, SEEK_SET) == -1) {
      ERROR_LOG("Failed to seek to chunk %lld in file 1", chunk);
      goto end;
    }
    if (read(file2, &buf2, PAGE_SIZE) == -1) {
      ERROR_LOG("Failed to read page %lld from file 2 while comparing", chunk);
      goto end;
    }
    if (memcmp(&buf1, &buf2, PAGE_SIZE) != 0) {
      ERROR_LOG("Files are not equal, chunk %lld differs", chunk);
      goto end;
    }
  }
  // Size and all pages are identical, files must be the same.
  equal = 0;
end:
  return equal;
}

// Validates the internal temp file with a reference file.
//
// args: an open file handle to a valid image
//
// return: 0 if the temp_file has identical content as the reference file
//         See filecmp() for other cases
//
int validate_test_image(const char const *reference_image_path) {
  int result = -1;
  int reference_image = -1;

  reference_image = open(reference_image_path, O_RDONLY);
  if (reference_image == -1) {
    ERROR_LOG("Failed to open reference image: %s", reference_image_path);
    goto error;
  }
  result = filecmp(temp_file, reference_image);
  close(reference_image);
error:
  return result;
}

// Creates a fictional memory map for testing with the mmap functions
//
// args: mmap is a pointer which recieves the test memory map
//       num_segments is the number of segments the test memory map will contain
//       desc_size is the size in bytes of an individual descriptor in the map
//       seg_size is the number of pages, each segment is comprised of
//
// return: EXIT_SUCCESS or EXIT_FAILURE
//
unsigned int init_test_mmap(uint8_t **mmap, unsigned int num_segments,
                            unsigned int desc_size, unsigned int seg_size) {
  *mmap = (uint8_t *)malloc(sizeof(EfiMemoryRange) * num_segments);
  if (*mmap == NULL) {
    ERROR_LOG("Failed to allocate memory for test memory map");
    return EXIT_FAILURE;
  }
  for (int segnum = 0; segnum < num_segments; segnum++) {
    EfiMemoryRange *segment = (EfiMemoryRange *)(*mmap + (segnum * desc_size));
    segment->Type = segnum % 15;  // Test each type once (there are 15)
    segment->PhysicalStart = segnum * seg_size * PAGE_SIZE;
    segment->VirtualStart = 0;  // Not really interesting for imaging
    segment->NumberOfPages = seg_size;
    segment->Attribute = 0;
  }
  return EXIT_SUCCESS;
}

// Instead of issuing an ioctl, this function will return test data.
int mock_ioctl(int fd, unsigned long request, void *outptr) {
  int status = -1;
  unsigned int result;

  switch (request) {
    case PMEM_IOCTL_GET_MMAP:
      result = init_test_mmap(outptr, kNumMemorySegments,
                              sizeof(EfiMemoryRange), kNumTestPages);
      if (result == EXIT_FAILURE) {
        ERROR_LOG("Failed to create test memory map, aborting tests");
        goto error;
      }
      break;

    case PMEM_IOCTL_GET_MMAP_SIZE:
      *(int32_t *)outptr = kNumMemorySegments * sizeof(EfiMemoryRange);
      break;

    case PMEM_IOCTL_GET_MMAP_DESC_SIZE:
      *(int32_t *)outptr = sizeof(EfiMemoryRange);
      break;
  }
  status = 0;
error:
  return status;
}

// Tests will not call into file opening functions, therefore any calls to this
// functions are invalid.
int mock_open(const char *path, int flags) {
  return -1; // Illegal fd
}

// Tests will not call into file opening functions, therefore any calls to this
// functions are invalid.
int mock_close(int fd) {
  return -1; // Illegal fd
}

// Writes to the dump file will be stored in the global temp file for
// comparison with prepared test images.
ssize_t mock_write(int fd, const void *buf, size_t nbytes) {
  // The imager should only write to the dumpfile.
  assert(fd == DUMP_FILE);
  // for now just skip writing and simulate success.
  return write(temp_file, buf, nbytes);
}

// Reads from a buffer with test data instead of a file.
ssize_t mock_read(int fd, void *buf, size_t nbytes) {
  // Reads should only occur from the memory device
  // everything else is a bug.
  assert(fd == MEM_DEV);
  // The imager should never read more than one page.
  assert(nbytes == PAGE_SIZE);
  // All reads are simulated to contain a sequence of the test byte.
  memset(buf, kTestByte, nbytes);
  // Mocked reads never fail, except on failed assertions.
  return nbytes;
}

// Seeks in the test data.
off_t mock_lseek(int fd, off_t offset, int whence) {
  off_t pos = 0;

  // No seeking allowed except in the mock files
  assert(fd == MEM_DEV || fd == DUMP_FILE);
  // Only absolute seeking is used
  assert(whence == SEEK_SET);
  switch (fd) {
    case MEM_DEV:
      // We don't really seek the memory device as it will always return the
      // same sequence of data anyways.
      pos = offset;
      break;

    case DUMP_FILE:
      pos = lseek(temp_file, offset, whence);
      if (pos != offset) {
        ERROR_LOG("Failed to seek in dump file");
      }
      break;
  }
  return pos;
}
