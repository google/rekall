// Provides functionality for manipulating ELF sections and shdr.
//
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

#ifndef _REKALL_TOOL_ELF_RELOCATIONS_H_
#define _REKALL_TOOL_ELF_RELOCATIONS_H_

#include "elf_generic.h"

struct ELF_OBJ_T;
typedef struct ELF_OBJ_T ELF_OBJ;

// Parse the section table and find a rela section refering to the given section
ELF_ERROR elf_rela_section(ELF_OBJ *obj, Elf_Word section_idx, Elf_Shdr **rela,
    Elf_Word *rela_idx);
// Finds all relocations to a specific symbol in an ELF_RELA section..
Elf_Rela **elf_find_all_rela_in_sec(ELF_OBJ *obj, Elf_Shdr *rela_section,
    Elf_Word symbol_idx, Elf_Word *num_rela);
// Finds out if an object has a relocation of a specific symbol into another
// symbol. E.g. if there is a relocation for a function into a struct.
ELF_ERROR elf_has_rela_to_sym(ELF_OBJ *obj, const char *sym_name,
    const char *rel_sym_name);
// Finds the first relocation of a specific symbol into another symbol
ELF_ERROR elf_find_rela_to_sym(ELF_OBJ *obj, char *sym_name, char *rel_sym_name,
    Elf_Off *sym_off);

#endif // _REKALL_TOOL_ELF_RELOCATIONS_H_

