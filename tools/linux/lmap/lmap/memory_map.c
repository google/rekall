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

#include <elf.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "../elfrelink/elf_generic.h"
#include "../log/log.h"
#include "memory_map.h"

const char *iomem_path = "/proc/iomem";
const char *iomem_ram_str = "System RAM";
static const unsigned int INITIAL_CAPACITY = 100;

// Allocates memory for the memory ranges in this vector,
// the caller must provide memory for the mm struct.
ELF_ERROR memory_map_init(MEMORY_MAP *mm) {
  mm->size = 0;
  mm->capacity = INITIAL_CAPACITY;
  if ((mm->ranges = (MEMORY_RANGE *)malloc(
      sizeof(MEMORY_RANGE) * mm->capacity)) == NULL) {
    log_print(LL_ERR, "Couldn't allocate memory for memory map");
    return ELF_FAILURE;
  }
  return ELF_SUCCESS;
}

// Frees the memory ranges in this map
void memory_map_free(MEMORY_MAP *mm) {
  free(mm->ranges);
}

// When parsing the memory map ranges can be added to the end,
// but random access is not implemented.
ELF_ERROR memory_map_append(MEMORY_MAP *mm, size_t run_start, size_t pages,
    off_t file_offset) {
  // double capacity if full to avoid too many realloc calls
  if (mm->size >= mm->capacity) {
    mm->capacity *= 2;
    // If realloc fails we still want to keep our data,
    // so copy the new ptr only on success...
    MEMORY_RANGE *new_ranges = (MEMORY_RANGE *)realloc(
        mm->ranges, sizeof(MEMORY_RANGE) * mm->capacity);
    if (new_ranges == NULL) {
      log_print(LL_ERR, "Failed to increase size of memory map, can't add run "
          "[%#016llx : %#016llx]", run_start, pages);
      return ELF_FAILURE;
    } else {
      mm->ranges = new_ranges;
    }
  }
  mm->ranges[mm->size].start = run_start;
  mm->ranges[mm->size].pages = pages;
  mm->ranges[mm->size].file_offset = file_offset;
  mm->size++;
  return ELF_SUCCESS;
}

// You can always access a range in the map
ELF_ERROR memory_map_get(MEMORY_MAP *mm, size_t idx, MEMORY_RANGE **range) {
  if (idx >= mm->size) {
    log_print(LL_ERR, "Can't get item %lld from memory map, has only %lld "
        "members", idx, mm->size);
    return ELF_FAILURE;
  }
  // Set the callers pointer to the desired index
  *range = mm->ranges + idx;
  return ELF_SUCCESS;
}

// Parses /proc/iomem and creates a map of all System RAM ranges.
ELF_ERROR get_physical_memory_map(MEMORY_MAP *mm) {
  FILE *fp = NULL;
  char buf[BUFSIZ];
  char run_type[64];
  size_t run_start = 0;
  size_t run_end = 0;
  size_t run_pages = 0;

  if ((fp = fopen(iomem_path, "r")) == NULL) {
    log_print(LL_ERR, "Can't open memory map at '%s'", iomem_path);
    return ELF_FAILURE;
  }
  while (fgets(buf, sizeof(buf), fp) != NULL) {
    if (sscanf(buf, "%016lx-%016lx : %64[^\n]", &run_start, &run_end, run_type)
        != 3) {
      log_print(LL_ERR, "Failed to parse line '%s' from %s, "
          "got %016lx-%016lx : %s", buf, iomem_path, run_start, run_end,
          run_type);
      return ELF_FAILURE;
    }
    // We are only interested in physical memory ranges
    if (strncmp(run_type, iomem_ram_str, strlen(iomem_ram_str)) == 0) {
      // The end address of runs in iomem is inclusive
      run_pages = (run_end + 1 - run_start) / PAGE_SIZE;
      if (memory_map_append(mm, run_start, run_pages, run_start)
          != ELF_SUCCESS) {
        log_print(LL_ERR, "Failed to insert range %016lx (%ld pages) "
            "into memory map", run_start, run_pages);
        return ELF_FAILURE;
      }
      log_print(LL_DBG, "inserted range %016lx (%ld pages)", run_start,
          run_pages);
    }
  }
  if (mm->size > 0) {
    return ELF_SUCCESS;
  }
  // If we didn't find any ranges there is no valid memory map and we fail
  return ELF_FAILURE;
}

// Iterates over a memory map and prints it to the screen
void memory_map_print(MEMORY_MAP *mm) {
  MEMORY_RANGE *curr_range;

  if (mm->size == 0) {
    log_print(LL_ERR, "Memory map is empty");
  } else {
    log_print(LL_LOG, "Memory map has these valid physical ranges: ");
    for (size_t i = 0; i < mm->size; i++) {
      if (memory_map_get(mm, i, &curr_range) != ELF_SUCCESS) {
        log_print(LL_ERR, "Memory map is corrupt, item %ld does not exist!", i);
        break;
      }
      // the end of a range is inclusive, thus the -1
      log_print(LL_LOG, "\tOffset: %#016lx - %#016lx", curr_range->start,
          curr_range->start + curr_range->pages * PAGE_SIZE - 1);
    }
  }
}
