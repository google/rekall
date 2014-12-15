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

#define _LARGEFILE64_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <strings.h>
#include <sys/types.h>
#include <unistd.h>

#include "../elfrelink/elf_generic.h"
#include "../log/log.h"
#include "memory_map.h"

// Initialize an ELF header with default values for a core dump file
// and a specific number of program headers.
//
// args: header is a pointer to the elf header to initialize.
//       num_segments is the number of program headers to add to this header.
//
void prepare_elf_header(Elf_Ehdr *header, unsigned int num_segments) {
  // All values that are unset will be zero
  bzero(header, sizeof(Elf_Ehdr));
  // We create a 64 bit core dump file with one section
  // for each physical memory segment.
  header->e_ident[0] = ELFMAG0;
  header->e_ident[1] = ELFMAG1;
  header->e_ident[2] = ELFMAG2;
  header->e_ident[3] = ELFMAG3;
  header->e_ident[4] = ELFCLASS64;
  header->e_ident[5] = ELFDATA2LSB;
  header->e_ident[6] = EV_CURRENT;
  header->e_type     = ET_CORE;
  header->e_machine  = EM_X86_64;
  header->e_version  = EV_CURRENT;
  header->e_phoff    = sizeof(Elf_Ehdr);
  header->e_ehsize   = sizeof(Elf_Ehdr);
  header->e_phentsize= sizeof(Elf_Phdr);
  header->e_phnum    = num_segments;
  header->e_shentsize= sizeof(Elf_Shdr);
}

// Initialize an ELF program header with a memory range.
//
// args: program_header is a pointer to an Elf_Phdr struct to initialize.
//       range is a pointer to the memory range to initialize the header with
//       file_offset is the raw offset into the elf file the segment will be
//       actually stored in.
//
void prepare_elf_program_header(Elf_Phdr *program_header, MEMORY_RANGE *range,
    uint64_t file_offset) {
  // All values that are unset will be zero
  bzero(program_header, sizeof(Elf_Phdr));
  program_header->p_type = PT_LOAD;
  program_header->p_paddr = range->start;
  program_header->p_memsz = range->pages * PAGE_SIZE;
  program_header->p_align = PAGE_SIZE;
  program_header->p_flags = PF_R;
  program_header->p_offset = file_offset;
  program_header->p_filesz = range->pages * PAGE_SIZE;
}

// Write a prepared header to the beginning of a file.
//
// args: file is an open filehandle to the output file.
//       header is a pointer to the buffer which stores the prepared header.
//       header_size is the size of the header in bytes.
//
// return: EXIT_SUCCESS or EXIT_FAILURE.
//
unsigned int write_header(int file, uint8_t *header, unsigned int header_size) {
  if (lseek64(file, 0, SEEK_SET) != 0) {
    log_print(LL_ERR, "Could not seek to beginning of file");
    return EXIT_FAILURE;
  }
  if (write(file, header, header_size) != header_size) {
    log_print(LL_ERR, "Failed to write header");
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}

// Write a segment of physical memory into a binary file. This segment must be
// accessible, otherwise the function will return 0.
//
// args: segment is a struct describing the position and size of the segment.
//       mem_dev is an open filehandle to the /dev/pmem device.
//       dump_file is an open filehandle to the image file.
//       file_offset is the offset in the output file to write the segment to.
//
// return: the number of bytes written.
//
unsigned int write_segment(MEMORY_RANGE *segment, int mem_dev, int dump_file,
    size_t file_offset) {
  size_t segment_size = segment->pages * PAGE_SIZE;
  size_t page = segment->file_offset;
  size_t end = segment->file_offset + segment_size;
  uint8_t page_buf[PAGE_SIZE];

  // Dump contiguous segments one page at a time
  while (page < end) {
    if (lseek64(mem_dev, page, SEEK_SET) < 0) {
      log_print(LL_ERR, "Could not seek to page in memory device");
      return EXIT_FAILURE;
    }
    if (read(mem_dev, page_buf, PAGE_SIZE) != PAGE_SIZE) {
      log_print(LL_ERR, "Failed to read page");
      perror("[-] error: ");
      return EXIT_FAILURE;
    }
    // Copy the page to the indicated offset in the file
    if (lseek64(dump_file, file_offset, SEEK_SET) < 0) {
      log_print(LL_ERR, "Could not seek to segment in dump file");
      return EXIT_FAILURE;
    }
    if (write(dump_file, page_buf, PAGE_SIZE) != PAGE_SIZE) {
      log_print(LL_ERR, "Failed to write page");
      return EXIT_FAILURE;
    }
    // Advance the read and write pointers
    page += PAGE_SIZE;
    file_offset += PAGE_SIZE;
  }
  return EXIT_SUCCESS;
}

// Parse the mmap and dump each section into an elf core dump file.
// Memory holes are ignored and unreadable sections like MMIO are written as
// empty segments. For each segment a program header is created in the elf
// file, that documents the physical address range it occupied.
//
// args:
//       mm is a pointer to a memory map of the system
//       mem_dev is an open filehandle to the pmem device file (/dev/pmem).
//       dump_file is an open filehandle to which the image will be written.
//
// return: EXIT_SUCCESS or EXIT_FAILURE.
//
unsigned int dump_memory_elf(MEMORY_MAP *mm, int mem_dev, int dump_file) {
  unsigned int status = EXIT_FAILURE;
  MEMORY_RANGE *curr_range = NULL;
  size_t curr_idx = 0;
  uint64_t file_offset = 0;
  uint64_t phys_as_size = 0;
  uint64_t bytes_imaged = 0;
  unsigned int headers_bufsize = 0;
  uint8_t *elf_headers_buf = NULL;
  Elf_Ehdr *elf_header = NULL;
  Elf_Phdr *program_header = NULL;

  // Prepare an elf phdr for each memory range and 1 ehdr for the file
  headers_bufsize = (
      sizeof(Elf_Ehdr) + mm->size * sizeof(Elf_Phdr));
  if ((elf_headers_buf = (uint8_t *)malloc(headers_bufsize)) == NULL) {
    log_print(LL_ERR, "Could not allocate memory for ELF headers");
    goto error_headers;
  }
  // The ELF header is at the beginning of the buffer
  elf_header = (Elf_Ehdr *)elf_headers_buf;
  // The program headers come right after the elf header
  program_header = (Elf_Phdr *)(elf_headers_buf + sizeof(Elf_Ehdr));
  prepare_elf_header(elf_header, mm->size);
  // Data will be written right after the header and load commands
  file_offset = headers_bufsize;
  log_print(LL_LOG, "Starting to dump memory");
  // Iterate over each section in the physical memory map and write it to disk.
  for (curr_idx = 0; curr_idx < mm->size; curr_idx++) {
    if (memory_map_get(mm, curr_idx, &curr_range) != ELF_SUCCESS) {
      log_print(LL_ERR, "Memory map corrupted, unable to write memory dump");
      return status;
    }
    uint64_t segment_size = curr_range->pages * PAGE_SIZE;
    prepare_elf_program_header(program_header, curr_range, file_offset);
    log_print(LL_NNL, "[%016llx - %016llx] ", curr_range->start,
        curr_range->start + segment_size - 1);
    if (write_segment(curr_range, mem_dev, dump_file, file_offset)
        == EXIT_FAILURE) {
      log_print(LL_ERR, "Failed to dump segment %d\n", curr_idx);
      goto error;
    }
    file_offset += segment_size;
    bytes_imaged += segment_size;
    log_print(LL_MSG, "[WRITTEN]");
    program_header++;
    // Calculate statistics
    uint64_t end_addr = curr_range->start + curr_range->pages * PAGE_SIZE;
    if (end_addr > phys_as_size) {
      phys_as_size = end_addr;
    }
  }
  write_header(dump_file, elf_headers_buf, headers_bufsize);
  log_print(LL_LOG, "Acquired %lld pages (%lld bytes)",
            bytes_imaged / PAGE_SIZE, bytes_imaged);
  log_print(LL_LOG, "Size of accessible physical address space: %lld bytes "
      "(%lld segments)", phys_as_size, curr_idx);
  status = EXIT_SUCCESS;
error:
  free(elf_headers_buf);
error_headers:
  return status;
}
