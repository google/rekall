// Copyright 2013 Google Inc. All Rights Reserved.
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

#ifndef _REKALL_TOOL_ELF_MEMORY_MAP_H_
#define _REKALL_TOOL_ELF_MEMORY_MAP_H_

#include <stdlib.h>
#include <sys/types.h>

#include "../elfrelink/elf_generic.h"

#define PAGE_SIZE 4096

// Simple description of a valid memory range,
// start is the starting offset,
// pages the number of pages valid from that offset.
// file_offset is the offset inside the device file,
// from which this range can be read.
typedef struct MEMORY_RANGE_T {
  size_t start;
  size_t pages;
  off_t file_offset;
} MEMORY_RANGE;

// The memory map is a simple vector of ranges
typedef struct MEMORY_MAP_T {
  size_t size;
  size_t capacity;
  MEMORY_RANGE *ranges;
} MEMORY_MAP;

const char *iomem_path;
const char *iomem_ram_str;

// Allocates memory for the memory ranges in this vector,
// the caller must provide memory for the mm struct.
ELF_ERROR memory_map_init(MEMORY_MAP *mm);
// Frees the memory ranges in this map
void memory_map_free(MEMORY_MAP *mm);
// When parsing the memory map ranges can be added to the end,
// but random access is not implemented.
ELF_ERROR memory_map_append(MEMORY_MAP *mm, size_t run_start, size_t pages,
    off_t file_offset);
// You can always access a range in the map
ELF_ERROR memory_map_get(MEMORY_MAP *mm, size_t idx, MEMORY_RANGE **range);
// Parses /proc/iomem and creates a map of all System RAM ranges.
ELF_ERROR get_physical_memory_map(MEMORY_MAP *mm);
// Iterates over a memory map and prints it to the screen
void memory_map_print(MEMORY_MAP *mm);

#endif // _REKALL_TOOL_ELF_MEMORY_MAP_H_
