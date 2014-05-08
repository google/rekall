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

#ifndef _REKALL_TOOL_ELF_GENERIC_H_
#define _REKALL_TOOL_ELF_GENERIC_H_

#include <elf.h>

#ifdef __x86_64
#define Elf_Ehdr Elf64_Ehdr
#define Elf_Shdr Elf64_Shdr
#define Elf_Phdr Elf64_Phdr
#define Elf_Sym Elf64_Sym
#define Elf_Rel Elf64_Rel
#define Elf_Rela Elf64_Rela
#define Elf_Off Elf64_Off
#define Elf_Addr Elf64_Addr
#define Elf_Half Elf64_Half
#define Elf_Word Elf64_Word
#define Elf_Xword Elf64_Xword
#define Elf_Sxword Elf64_Sxword
#define Elf_Entsize Elf64_Xword
#define Elf_Addend Elf64_Sxword
#define ELF_MACHINE EM_X86_64
#define ELF_R_SYM ELF64_R_SYM
#define ELF_R_TYPE ELF64_R_TYPE
#define ELF_R_INFO ELF64_R_INFO
#define ELF_R_PC32 R_X86_64_PC32
#define ELF_R_ABS R_X86_64_64
#define ELF_R_NONE R_X86_64_NONE
#define ELF_ST_BIND ELF64_ST_BIND
#define ELF_ST_TYPE ELF64_ST_TYPE
#define ELF_ST_INFO ELF64_ST_INFO
#else
#define Elf_Ehdr Elf32_Ehdr
#define Elf_Shdr Elf32_Shdr
#define Elf_Phdr Elf32_Phdr
#define Elf_Sym Elf32_Sym
#define Elf_Rel Elf32_Rel
#define Elf_Rela Elf32_Rela
#define Elf_Off Elf32_Off
#define Elf_Addr Elf32_Addr
#define Elf_Half Elf32_Half
#define Elf_Word Elf32_Word
#define Elf_Xword Elf32_Xword
#define Elf_Sxword Elf32_Sxword
#define ELF_MACHINE EM_386
#define Elf_Entsize Elf32_Word
#define Elf_Addend Elf32_Sword
#define ELF_R_SYM ELF32_R_SYM
#define ELF_R_TYPE ELF32_R_TYPE
#define ELF_R_INFO ELF32_R_INFO
#define ELF_R_PC32 R_386_PC32
#define ELF_R_ABS R_386_32
#define ELF_R_NONE R_386_NONE
#define ELF_ST_BIND ELF32_ST_BIND
#define ELF_ST_TYPE ELF32_ST_TYPE
#define ELF_ST_INFO ELF32_ST_INFO
#endif

typedef enum ELF_ERROR_T {
  ELF_SUCCESS = 0,
  ELF_FAILURE
} ELF_ERROR;

#endif // _REKALL_TOOL_ELF_GENERIC_H_
