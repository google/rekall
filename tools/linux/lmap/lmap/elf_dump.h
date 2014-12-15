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

#ifndef _REKALL_TOOL_ELF_DUMP_H_
#define _REKALL_TOOL_ELF_DUMP_H_

#include "../elfrelink/elf_generic.h"
#include "memory_map.h"

// Initialize an ELF header with default values for a core dump file
// and a specific number of program headers.
void prepare_elf_header(Elf_Ehdr *header, unsigned int num_segments);
// Initialize an ELF program header with data from an EFI segment descriptor.
void prepare_elf_program_header(Elf_Phdr *program_header, MEMORY_RANGE *range,
    uint64_t file_offset);
// Write a prepared header to the beginning of a file.
unsigned int write_header(int file, uint8_t *header, unsigned int header_size);
// Write a segment of physical memory into a binary file. This segment must be
// accessible, otherwise the function will return 0.
unsigned int write_segment(MEMORY_RANGE *segment, int mem_dev, int dump_file,
    size_t file_offset);
// Parse the mmap and dump each section into an elf core dump file.
unsigned int dump_memory_elf(MEMORY_MAP *mm, int mem_dev, int dump_file);

#endif // _REKALL_TOOL_ELF_KCORE_H_
