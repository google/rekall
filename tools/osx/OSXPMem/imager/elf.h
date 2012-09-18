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

#ifndef _VOLATILITY_ELF_H_
#define _VOLATILITY_ELF_H_

#include <stdint.h>

#define ELFMAG0       0x7f  // Byte 0 of ELF Magic
#define ELFMAG1       'E'   // Byte 1 of ELF Magic
#define ELFMAG2       'L'   // Byte 2 of ELF Magic
#define ELFMAG3       'F'   // Byte 3 of ELF Magic

#define ELFCLASS64    2     // 64 Bit ELF File
#define EV_CURRENT    1     // Current ELF version
#define ET_CORE       4     // ELF Core Dump
#define EM_X86_64     62    // Intel x86-64 Architecture

#define ELFDATA2LSB   1     // Little Endian 2-Complement Data
#define ELFDATA2MSB   2     // Big Endian 2-Complement Data
#define PT_LOAD       1     // Program Header Segment Type: Loadable

// ELF-64 File Header
typedef struct elf64_ehdr_ {
  unsigned char e_ident[16];  // ELF Magic and Attributes
  uint16_t      e_type;       // File Type
  uint16_t      e_machine;    // Architecture
  uint32_t      e_version;    // ELF Version
  uint64_t      e_entry;      // Program Entry Point
  uint64_t      e_phoff;      // Offset of Program Headers
  uint64_t      e_shoff;      // Offset of Section Headers
  uint32_t      e_flags;      // Processor Specific Flags
  uint16_t      e_ehsize;     // Size of ELF Header in Bytes
  uint16_t      e_phentsize;  // Size of individual Program Header Entries
  uint16_t      e_phnum;      // Number of Program Header Entries
  uint16_t      e_shentsize;  // Size of individual Section Header Entries
  uint16_t      e_shnum;      // Number of Section Header Entries
  uint16_t      e_shstrndx;   // Section Header String Table Index
} elf64_ehdr;

// ELF-64 Program Header
typedef struct elf64_phdr_ {
  uint32_t      p_type;     // Segment Type
  uint32_t      p_flags;    // Segment Flags
  uint64_t      p_offset;   // Segment File Offset
  uint64_t      p_vaddr;    // Segment Virtual Address
  uint64_t      p_paddr;    // Segment Physical Address
  uint64_t      p_filesz;   // Segment Size in File
  uint64_t      p_memsz;    // Segment Size in Memory
  uint64_t      p_align;    // Segment Alignment
} elf64_phdr;

// ELF-64 Section Header
typedef struct elf64_shdr_ {
  uint32_t      sh_name;       // Section Name
  uint32_t      sh_type;       // Section Type
  uint64_t      sh_flags;      // Section Flags
  uint64_t      sh_addr;       // Section Virtual Address
  uint64_t      sh_offset;     // Section File Offset
  uint64_t      sh_size;       // Section Size in Bytes
  uint32_t      sh_link;       // Link to other Section
  uint32_t      sh_info;       // Section Information
  uint64_t      sh_addralign;  // Section Alignment
  uint64_t      sh_entsize;    // Entry Size if Table
} elf64_shdr;

#endif  // _VOLATILITY_ELF_H_
