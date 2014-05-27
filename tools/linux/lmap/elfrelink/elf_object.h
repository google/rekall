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

#ifndef _REKALL_TOOL_ELF_OBJECT_H_
#define _REKALL_TOOL_ELF_OBJECT_H_

#define _GNU_SOURCE

#include <stdlib.h>

#include "elf_generic.h"

typedef struct ELF_OBJ_T {
  // general virtual functions
  ELF_ERROR (*get_ehdr)(struct ELF_OBJ_T *obj, Elf_Ehdr **ehdr);
  ELF_ERROR (*get_shdr)(struct ELF_OBJ_T *obj, Elf_Shdr **shdr);
  ELF_ERROR (*get_shstrtab)(struct ELF_OBJ_T *obj, Elf_Shdr **shstrtab,
      Elf_Word *shstrtab_idx);
  // Section related virtual functions
  ELF_ERROR (*section_by_idx)(struct ELF_OBJ_T *obj, Elf_Word idx,
      Elf_Shdr **section);
  ELF_ERROR (*section_by_name)(struct ELF_OBJ_T *obj, char const *name,
      Elf_Word *idx, Elf_Shdr **section);
  ELF_ERROR (*section_by_suffix)(struct ELF_OBJ_T *obj, char const *name,
      Elf_Word *idx, Elf_Shdr **section);
  ELF_ERROR (*section_after_offset)(struct ELF_OBJ_T *obj, Elf_Off offset,
      Elf_Shdr **section, Elf_Word *section_idx);
  ELF_ERROR (*section_get_name)(struct ELF_OBJ_T *obj, Elf_Shdr *section,
      char **name);
  ELF_ERROR (*section_get_contents)(struct ELF_OBJ_T *obj, Elf_Shdr *section,
      uint8_t **contents);
  ELF_ERROR (*section_move_back)(struct ELF_OBJ_T *obj, Elf_Word section_idx,
      Elf_Off offset);
  // Symbol related virtual functions
  ELF_ERROR (*symbol_get_name)(struct ELF_OBJ_T *obj, Elf_Word strtab_off,
      char **name);
  ELF_ERROR (*symbol_by_idx)(struct ELF_OBJ_T *obj, Elf_Word idx,
      Elf_Sym **symbol);
  ELF_ERROR (*symbol_by_name)(struct ELF_OBJ_T *obj, char *name,
      Elf_Sym **symbol, Elf_Word *idx);
  ELF_ERROR (*symbol_by_suffix)(struct ELF_OBJ_T *obj, const char *suffix,
      Elf_Sym **sym, Elf_Word *idx);
  ELF_ERROR (*symbol_to_section)(struct ELF_OBJ_T *obj, Elf_Word sec_idx,
      Elf_Sym **symbol, Elf_Word *idx);
  ELF_ERROR (*symbol_exist)(struct ELF_OBJ_T *obj, char **symbols,
      size_t num_syms);
  ELF_ERROR (*symbol_exist_suffix)(struct ELF_OBJ_T *obj, char **symbols,
      size_t num_syms);
  ELF_ERROR (*symbol_exist_named_suffix)(struct ELF_OBJ_T *obj, char *name,
      char **suffixes, size_t num_syms);
  ELF_ERROR (*relocation_to_section)(struct ELF_OBJ_T *obj,
      Elf_Word section_idx, Elf_Shdr **rela, Elf_Word *rela_idx);
//  ELF_ERROR (*relocation_to_symbol)(struct ELF_OBJ_T *obj, char *sym_name,
//      char *rel_sym_name, Elf_Off *sym_off);
  Elf_Rela** (*relocation_by_symbol)(struct ELF_OBJ_T *obj,
      Elf_Shdr *rela_section, Elf_Word symbol_idx, Elf_Word *num_rela);
  ELF_ERROR (*relocation_exist_to_sym)(struct ELF_OBJ_T *obj,
      const char *sym_name, const char *rel_sym_name);
  // The actual elf file in memory
  uint8_t *data;
  // The size of the elf file
  size_t size;
  // The size of the allocated buffer
  // (can be used to increase the size of the elf file)
  size_t bufsize;
} ELF_OBJ;

// Creates a new elf object from a file already in memory.
ELF_ERROR elf_from_mem(uint8_t *data, size_t len, ELF_OBJ *obj,
    size_t excess);
// Opens an elf relocatable object, loads it into memory, parses the headers
// and performs sanity checking. Caller must free the allocated buffer.
ELF_ERROR elf_from_file(const char *path, ELF_OBJ *obj, size_t excess);
// Writes an object out to the filesystem
ELF_ERROR elf_to_file(const char *path, ELF_OBJ *obj);
// Finds out if the next section in the file is actually the shdr table
ELF_ERROR elf_shdrtab_is_next(ELF_OBJ *obj, Elf_Word offset);
// Moves the section header table back in the file.
ELF_ERROR elf_move_shtab_back(ELF_OBJ *obj, Elf_Off offset);
// Verifies that a valid elf header for a ET_REL file is present and the flags
// for machine type and architecture match this binary.
ELF_ERROR elf_verify_ehdr(Elf_Ehdr *ehdr);
// Parse the headers in an elf object, populate the pointers to important
// sections and data structures and perform sanity checks.
ELF_ERROR elf_parse_headers(ELF_OBJ *obj);
// Removes any dependencies a module might have by overwriting the 'depends='
// string in .modinfo with zeroes.
ELF_ERROR elf_clean_dependencies(ELF_OBJ *obj);
// Change the module name by overwriting it in section .gnu.linkone.this_module
ELF_ERROR elf_rename_module(ELF_OBJ *obj, char *old_name, char *new_name);
// Increases the size of an elf object by growing it at the end.
ELF_ERROR elf_enlarge_obj(ELF_OBJ *obj, Elf_Word amount);
// Increases the size of a section. Also pushes all other sections and the
// section header table back, if they are next to it.
ELF_ERROR elf_enlarge_section(ELF_OBJ *obj, Elf_Word section_idx,
Elf_Word amount);
// Add a new section header to the section header table.
// Resizes the table and moves subsequent sections back.
ELF_ERROR elf_add_shdr(ELF_OBJ *obj, Elf_Shdr *shdr, Elf_Word name,
    Elf_Word section_off, Elf_Word *shdr_idx);
// Increases the size of the symbol table and adds a new entry.
ELF_ERROR elf_add_symtab_entry(ELF_OBJ *obj, Elf_Sym *sym, Elf_Word *idx);
// Adds a new string to a given string table. Stores the offset where it placed
// the new string in 'offset'.
ELF_ERROR elf_add_strtab_entry(ELF_OBJ *obj, Elf_Word strtab_idx, char *entry,
    Elf_Word *offset);
// Frees any memory the object's members occupy
ELF_ERROR elf_free_obj(ELF_OBJ *obj);
// Checks if a pointer is actually inside an elf object
ELF_ERROR elf_ptr_invalid(ELF_OBJ *obj, uint8_t *ptr);
// Checks if a string ends in a specific suffix.
ELF_ERROR string_has_suffix(const char *string, const char *suffix);

#endif // _REKALL_TOOL_ELF_OBJECT_H_
