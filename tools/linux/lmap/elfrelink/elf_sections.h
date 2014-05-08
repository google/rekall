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

#ifndef _REKALL_TOOL_ELF_SECTIONS_H_
#define _REKALL_TOOL_ELF_SECTIONS_H_

#include "elf_generic.h"

struct ELF_OBJ_T;
typedef struct ELF_OBJ_T ELF_OBJ;

// Parses the section headers and returns a specific section.
ELF_ERROR elf_get_section(ELF_OBJ *obj, Elf_Word idx, Elf_Shdr **section);
// Parse the section table and find a specific section by name.
ELF_ERROR elf_get_section_by_name(ELF_OBJ *obj, char const *name,
    Elf_Word *idx, Elf_Shdr **section);
// Parse the section table and find a specific section by name.
ELF_ERROR elf_get_section_by_suffix(ELF_OBJ *obj, char const *suffix,
    Elf_Word *idx, Elf_Shdr **section);
// Parses the section headers string table and point 'name' to the name of a
// specific section.
ELF_ERROR elf_get_section_name(ELF_OBJ *obj, Elf_Shdr *section, char **name);
// Parses a given section header and returns a pointer to the contents.
ELF_ERROR elf_get_section_contents(ELF_OBJ *obj, Elf_Shdr *section,
                                   uint8_t **contents);
// Parse the section headers and gets the next section after a specific offset
// in the file.
ELF_ERROR elf_get_section_after(ELF_OBJ *obj, Elf_Off offset,
    Elf_Shdr **section, Elf_Word *section_idx);
// Moves the given section back in the file, creating space to insert a new
// section. Works recursively, so any sections behind it are also moved.
ELF_ERROR elf_move_section_back(ELF_OBJ *obj, Elf_Word section_idx,
Elf_Off offset);

#endif // _REKALL_TOOL_ELF_SECTIONS_H_

