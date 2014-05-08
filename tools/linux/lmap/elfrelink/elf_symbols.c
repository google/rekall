// Provides functionality for manipulating ELF symbol and string tables.
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

#include <string.h>

#include "elf_object.h"
#include "elf_symbols.h"
#include "../log/log.h"

// Parses the string table and point 'name' to the name of a specific symbol.
ELF_ERROR elf_get_symbol_name(ELF_OBJ *obj, Elf_Word strtab_off, char **name) {
  Elf_Shdr *strtab = NULL;
  Elf_Word strtab_idx = 0;

  if (obj->section_by_name(obj, ".strtab", &strtab_idx, &strtab)
      != ELF_SUCCESS) {
    log_print(LL_ERR, "Can't get symbol name %d, .strtab not found",
        strtab_off);
    return ELF_FAILURE;
  }
  *name = (char *) (obj->data + strtab->sh_offset + strtab_off);
  if (elf_ptr_invalid(obj, (uint8_t *) *name)) {
    log_print(LL_ERR, "Can't find symbol at offset %d", strtab_off);
    return ELF_FAILURE;
  }
  return ELF_SUCCESS;
}

// Finds a symbol table entry by index
ELF_ERROR elf_get_symbol(ELF_OBJ *obj, Elf_Word idx, Elf_Sym **symbol) {
  Elf_Shdr *symtab = NULL;
  Elf_Word symtab_idx = 0;

  if (obj->section_by_name(obj, ".symtab", &symtab_idx, &symtab)
      != ELF_SUCCESS) {
    log_print(LL_ERR, "Can't get symbol %d, .symtab not found", idx);
    return ELF_FAILURE;
  }
  *symbol = (Elf_Sym *) (obj->data + symtab->sh_offset
      + idx * symtab->sh_entsize);
  if (elf_ptr_invalid(obj, (uint8_t *) *symbol)) {
    log_print(LL_ERR, "Can't find symbol %d", idx);
    return ELF_FAILURE;
  }
  return ELF_SUCCESS;
}
// Finds a symbol table entry referencing a specific section
ELF_ERROR elf_get_symbol_to_section(ELF_OBJ *obj, Elf_Word sec_idx,
    Elf_Sym **symbol, Elf_Word *idx) {
  Elf_Shdr *symtab = NULL;
  Elf_Word symtab_idx = 0, symtab_size = 0;

  if (obj->section_by_name(obj, ".symtab", &symtab_idx, &symtab)
      != ELF_SUCCESS) {
    log_print(LL_ERR, "Can't get symbol to section %d, .symtab not found",
        sec_idx);
    return ELF_FAILURE;
  }
  symtab_size = symtab->sh_size / symtab->sh_entsize;
  for (Elf_Word i = 0; i < symtab_size; i++) {
    if (elf_get_symbol(obj, i, symbol)) {
      log_print(LL_DBG, "Can't get symtab entry %d", i);
      continue;
    }
    if (((*symbol)->st_shndx == sec_idx) && (*symbol)->st_value == 0) {
      *idx = i;
      return ELF_SUCCESS;
    }
  }
  log_print(LL_DBG, "Can't find symbol referring to section %d in .symtab",
            sec_idx);
  return ELF_FAILURE;
}

// Parse the symbol and string tables to find a specific symbol by name.
ELF_ERROR elf_get_symbol_by_name(ELF_OBJ *obj, char *name,
    Elf_Sym **symbol, Elf_Word *idx) {
  char *curr_name;
  Elf_Shdr *symtab = NULL;
  Elf_Word symtab_idx = 0, symtab_size = 0;

  if (obj->section_by_name(obj, ".symtab", &symtab_idx, &symtab)
      != ELF_SUCCESS) {
    log_print(LL_ERR, "Can't get symbol %s, .symtab not found", name);
    return ELF_FAILURE;
  }
  symtab_size = symtab->sh_size / symtab->sh_entsize;
  for (Elf_Word i = 0; i < symtab_size; i++) {
    if (elf_get_symbol(obj, i, symbol)) {
      log_print(LL_DBG, "Can't get symtab entry %d", i);
      continue;
    }
    if (elf_get_symbol_name(obj, (*symbol)->st_name, &curr_name)) {
      log_print(LL_DBG, "Skipping unnamed symbol %d", i);
      continue;
    }
    if (!strcmp(name, curr_name)) {
      *idx = i;
      return ELF_SUCCESS;
    }
  }
  log_print(LL_DBG, "Can't find symbol %s", name);
  return ELF_FAILURE;
}

// Finds a symbol that ends in a specific suffix
//
// Args:
//  obj: ELF object to operate on
//  suffix: string suffix of the symbol to look for
//  sym: pointer to an Elf_Sym pointer to set if found
//  idx: pointer to the symbols index to set if found
//
ELF_ERROR elf_get_symbol_by_suffix(ELF_OBJ *obj, const char *suffix,
    Elf_Sym **sym, Elf_Word *idx) {
  char *curr_name;
  Elf_Shdr *symtab = NULL;
  Elf_Word symtab_idx = 0, symtab_size = 0;

  if (obj->section_by_name(obj, ".symtab", &symtab_idx, &symtab)
      != ELF_SUCCESS) {
    log_print(LL_ERR, "Can't get symbol %s, .symtab not found", suffix);
    return ELF_FAILURE;
  }
  symtab_size = symtab->sh_size / symtab->sh_entsize;
  for (Elf_Word i = 0; i < symtab_size; i++) {
    if (elf_get_symbol(obj, i, sym)) {
      log_print(LL_DBG, "Can't get symtab entry %d", i);
      continue;
    }
    if (elf_get_symbol_name(obj, (*sym)->st_name, &curr_name)) {
      log_print(LL_DBG, "Skipping unnamed symbol %d", i);
      continue;
    }
    if (string_has_suffix(curr_name, suffix) == ELF_SUCCESS) {
      *idx = i;
      return ELF_SUCCESS;
    }
  }
  return ELF_FAILURE;
}


// Checks if a given elf object contains a list of symbols.
//
// Args:
//  obj: ELF object to operate on
//  sym: array of strings that must be in the object
//  num_sym: length of sym
//
// Returns: ELF_SUCCESS if all symbols are inside a give elf object, ELF_ERROR
// otherwise.
//
ELF_ERROR elf_contains_syms(ELF_OBJ *obj, char **symbols, size_t num_syms) {
  Elf_Sym *tmp_sym;
  Elf_Word tmp_off;

  for (size_t i = 0; i < num_syms; i++) {
    if (elf_get_symbol_by_name(obj, symbols[i], &tmp_sym, &tmp_off)) {
      return ELF_FAILURE;
    }
    log_print(LL_DBG, "Found symbol %s", symbols[i]);
  }
  return ELF_SUCCESS;
}

// Checks if a given elf object contains symbols that end in a list of suffixes.
//
// Args:
//  obj: ELF object to operate on
//  sym: array of strings that must be in the object
//  num_sym: length of sym
//
// Returns: ELF_SUCCESS if all symbols are inside a give elf object, ELF_ERROR
// otherwise.
//
ELF_ERROR elf_contains_syms_with_suffix(ELF_OBJ *obj, char **suffixes,
    size_t num_syms) {
  Elf_Sym *tmp_sym;
  Elf_Word tmp_off;

  for (size_t i = 0; i < num_syms; i++) {
    if (elf_get_symbol_by_suffix(obj, suffixes[i], &tmp_sym, &tmp_off)) {
      return ELF_FAILURE;
    }
  }
  return ELF_SUCCESS;
}

// Same as above but prepends a name to the suffix before checking
ELF_ERROR elf_contains_syms_with_named_suffix(ELF_OBJ *obj, char *name,
  char **suffixes, size_t num_syms) {
  Elf_Sym *tmp_sym;
  Elf_Word tmp_off;
  char sym_name[128];

  for (size_t i = 0; i < num_syms; i++) {
    // build symbol name eg "lp" and "_read" to "lp_read"
    strncpy(sym_name, name, strlen(name) + 1);
    strncat(sym_name, suffixes[i], strlen(suffixes[i]));
    if (elf_get_symbol_by_name(obj, sym_name, &tmp_sym, &tmp_off)) {
      return ELF_FAILURE;
    }
    log_print(LL_DBG, "Found symbol %s", sym_name);
  }
  return ELF_SUCCESS;
}


