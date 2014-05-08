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

#ifndef _REKALL_TOOL_ELF_SYMBOLS_H_
#define _REKALL_TOOL_ELF_SYMBOLS_H_

#include <stdio.h>

#include "elf_generic.h"

struct ELF_OBJ_T;
typedef struct ELF_OBJ_T ELF_OBJ;

// Finds a symbol table entry by name
ELF_ERROR elf_get_symbol(ELF_OBJ *obj, Elf_Word idx, Elf_Sym **symbol);
// Parses the string table and point 'name' to the name of a specific symbol.
ELF_ERROR elf_get_symbol_name(ELF_OBJ *obj, Elf_Word idx, char **name);
// Parse the symbol and string tables to find a specific symbol by name.
ELF_ERROR elf_get_symbol_by_name(ELF_OBJ *obj, char *name, Elf_Sym **symbol,
    Elf_Word *idx);
// Finds a symbol that ends in a specific suffix
ELF_ERROR elf_get_symbol_by_suffix(ELF_OBJ *obj, const char *suffix,
    Elf_Sym **sym, Elf_Word *idx);
// Finds a symbol table entry referencing a specific section
ELF_ERROR elf_get_symbol_to_section(ELF_OBJ *obj, Elf_Word sec_idx,
    Elf_Sym **symbol, Elf_Word *idx);
// Checks if a given elf object contains a list of symbols.
ELF_ERROR elf_contains_syms(ELF_OBJ *obj, char **symbols, size_t num_syms);
// Checks if a given elf object contains symbols that end in a list of suffixes.
ELF_ERROR elf_contains_syms_with_suffix(ELF_OBJ *obj, char **suffixes,
    size_t num_syms);
// Same as above but prepends a name to the suffix before checking
ELF_ERROR elf_contains_syms_with_named_suffix(ELF_OBJ *obj, char *name,
    char **suffixes, size_t num_syms);

#endif // _REKALL_TOOL_ELF_SYMBOLS_H_
