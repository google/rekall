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

#ifndef _VOLATILITY_PMEM_IMAGER_H_
#define _VOLATILITY_PMEM_IMAGER_H_

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <mach/vm_param.h>
#include <mach-o/loader.h>
#include <pexpert/i386/boot.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

// This interface is available only since Snow Leopard (10.6).
#define MAX_OS_X_VERSION_MIN_REQUIRED 1060
#include <IOKit/kext/KextManager.h>

// GNU C Library ELF Headers
#include "elf.h"
// IOCTL numbers for the pmem kext.
#include "../pmem/pmem_ioctls.h"

// While it is clear these things should be static strings not macros,
// the macros we have to use to interact with IOKit require these strings to
// be literals, so we make an exception.
#define PMEM_KEXT_PATH "./pmem.kext"
#define PMEM_KEXT_IDENTIFIER "volatility.driver.pmem"

// This is externalized to simplify modifying the error output.
#define PMEM_ERROR_LOG(...) do { print_msg(ERR, "%s(%d): ", \
                                                __func__, __LINE__); \
                                      print_msg(ERR, __VA_ARGS__); \
                                      print_msg(ERR, " (%s)\n", \
                                                strerror(errno)); \
                                 } while (0)

typedef struct segment_command_64 segment_command_t;
typedef struct mach_header_64 mach_header_t;

// Loglevels for text output.
typedef enum {
  ERR = 0,  // Error messages
  STD = 1,  // Default log level
  DBG = 2   // Debug loglevel for verbose output
} loglevel_t;

extern loglevel_t loglevel;

// Formats for the memory dump file.
typedef enum {
  RAW_PADDED,
  MACH_O,
  ELF
} dumpformat_t;

// Get the physical memory map from the driver.
unsigned int get_mmap(uint8_t **mmap, unsigned int *mmap_size,
                      unsigned int *mmap_desc_size, int device_file);
// Convert the memory map to a human readable text representation.
char *mmap_tostring(uint8_t *mmap, const unsigned int mmap_size,
                    const unsigned int mmap_entry_size);
// Load driver, get mmap and display it to the user.
unsigned int display_mmap(const char const *device_file_path);
// Get the kernel directory table base from the driver.
unsigned int get_dtb(int fd, uint64_t *dtb);

// Functions for writing a padded raw image.
unsigned int dump_memory_raw(int mem_dev, int dump_file);

// Functions for writing ELF core dump images.
void prepare_elf_header(elf64_ehdr *header, unsigned int num_segments);
void prepare_elf_program_header(elf64_phdr *program_header,
                                EfiMemoryRange *segment, uint64_t file_offset);
unsigned int dump_memory_elf(int mem_dev, int dump_file);

// Functions for writing Mach-O core dump images.
void prepare_macho_header(mach_header_t *header, unsigned int num_segments);
void prepare_macho_segment(segment_command_t *load_command,
                           EfiMemoryRange *segment, uint64_t file_offset);
unsigned int dump_memory_macho(int mem_dev, int dump_file);

// Generic acquisition functions.
unsigned int write_header(int file, uint8_t *header, unsigned int header_size);
unsigned int write_segment(EfiMemoryRange *segment, int mem_dev,
                                  int dump_file, uint64_t file_offset);
// Dump physical memory to a file.
unsigned int dump_memory(char const *dump_file_path,
                         const char const *device_file_path);
// Determines if a segment is of an accessible type,
bool segment_accessible(EfiMemoryRange *segment);

// Convert the memory segment type to a human readable text representation.
const char const *physmem_type_tostring(int type);
// Print a log message.
void print_msg(loglevel_t level, const char *fmt, ...);
// Print a command line help text.
void display_usage(const char const *image_name);
// Load the pmem driver.
unsigned int load_kext(void);
// Unload the pmem driver.
unsigned int unload_kext(void);

#endif  // _VOLATILITY_PMEM_IMAGER_H_
