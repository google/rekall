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

#ifndef _REKALL_TOOL_ELFRELINK_H_
#define _REKALL_TOOL_ELFRELINK_H_

#include "elf_generic.h"
#include "elf_object.h"

// Replace a symbol value in .symtab with another one, effectively hooking
// calls to this symbol.
ELF_ERROR elf_hook_symbol(ELF_OBJ *obj, char *symbol_name, char *hook_name);
// Performs all relocation hooks for segment offset relocations for a section.
ELF_ERROR elf_hook_rela(ELF_OBJ *obj, Elf_Shdr *rel_section,
    Elf_Word section_idx, char *hook_name, Elf_Word target_offset);
// Performs all relocation hooks for segment offset relocations for a file.
ELF_ERROR elf_hook_all_relocations(ELF_OBJ *obj, char *section_name,
    char *hook_name, Elf_Word target_offset);
// Copy all symtab entries that reference symbols in section number 'src_idx' to
// to the symtab in 'dest_obj'. Also copy the names into 'dest_obj' strtab and
// fix all references in 'dest_obj'
ELF_ERROR elf_migrate_symbols(ELF_OBJ *src_obj, ELF_OBJ *dest_obj,
    Elf_Word src_idx, Elf_Word dest_idx);
// Migrate a relocation section from one module to another.
// Fix up all references to sections and symbols to adjust to target.
ELF_ERROR elf_migrate_rela(ELF_OBJ *src, ELF_OBJ *dst,
    Elf_Word rela_idx, Elf_Word sec_idx, Elf_Word dst_sec_idx, char *prefix);
// Injects an in-memory buffer into an elf file as a new section.
ELF_ERROR elf_inject_section(ELF_OBJ *obj, ELF_OBJ *src, uint8_t const *section,
    size_t len, Elf_Shdr *section_shdr, Elf_Word section_idx, char *name,
    Elf_Word *new_shdr_idx);
// Inject all sections of one elf object into another.
ELF_ERROR elf_inject_obj(ELF_OBJ *host, ELF_OBJ *parasite, char *parasite_name);

#endif // _REKALL_TOOL_ELFRELINK_H_
