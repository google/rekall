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

#include "elf_relocations.h"
#include "elf_object.h"
#include "elf_sections.h"
#include "elf_symbols.h"
#include "../log/log.h"

// Parse the section table and find a rela section refering to the given section
//
// Args:
//  obj: This pointer
//  section_idx: index of the section to which the relocations should apply
//  rela: pointer to the relocation section pointer to set
//  rela_idx: pointer to the relocation index to set
//
ELF_ERROR elf_rela_section(ELF_OBJ *obj, Elf_Word section_idx, Elf_Shdr **rela,
    Elf_Word *rela_idx) {
  Elf_Ehdr *ehdr;
  Elf_Shdr *section;

  if (obj->get_ehdr(obj, &ehdr) != ELF_SUCCESS) {
    log_print(LL_ERR, "Cant find relocations to section %d, ehdr not found",
        section_idx);
    return ELF_FAILURE;
  }
  for (int idx = 0; idx < ehdr->e_shnum; idx++) {
    if (elf_get_section(obj, idx, &section)) {
      log_print(LL_DBG, "Invalid section header %d, skipping", idx);
      continue;
    }
    if (section->sh_type == SHT_RELA && section->sh_info == section_idx) {
      *rela = section;
      *rela_idx = idx;
      return ELF_SUCCESS;
    }
  }
  log_print(LL_DBG, "Can't find rela to section %d", section_idx);
  return ELF_FAILURE;
}

// Finds all relocations to a specific symbol in an ELF_RELA section..
// Will also report sgment offset relative relocations if they match a symbols
// segment and offset. This function allocates memory so the returned heap array
// must be freed by the caller!
//
// Args:
//  obj: Pointer to the elf file object
//  rela_section: pointer to an ELF_RELA section of relocations
//  symbol: Pointer to the symbol to find relocations to
//  num_rela: size of rela array
//
//  Returns: Pointer to the allocated array of relas, or NULL on failure
//
Elf_Rela **elf_find_all_rela_in_sec(ELF_OBJ *obj, Elf_Shdr *rela_section,
    Elf_Word symbol_idx, Elf_Word *num_rela) {
  Elf_Rela *curr_rela;
  Elf_Word section_size = rela_section->sh_size / rela_section->sh_entsize;
  Elf_Sym *curr_sym, *symbol;
  Elf_Word curr_sym_idx;
  Elf_Rela **rela = NULL;
  *num_rela = 0;

  if (elf_get_symbol(obj, symbol_idx, &symbol)) {
    log_print(LL_ERR, "symbol %d doesn't exist", symbol_idx, symbol_idx);
    goto error;
  }
  for (Elf_Word i = 0; i < section_size; i++) {
    curr_rela = (Elf_Rela *) (obj->data + rela_section->sh_offset
        + i * rela_section->sh_entsize);
    if (elf_ptr_invalid(obj, (uint8_t *) curr_rela)) {
      log_print(LL_ERR, "Relocation entry %d invalid", i);
      continue;
    }
    curr_sym_idx = ELF_R_SYM(curr_rela->r_info);
    if (elf_get_symbol(obj, curr_sym_idx, &curr_sym)) {
      log_print(LL_ERR, "Rela %d references symbol %d that doesn't exist", i,
                curr_sym_idx);
      continue;
    }
    if (ELF32_ST_TYPE(curr_sym->st_info) == STT_SECTION) {
      // The relocation is relative to a section, not as straight forward.
      if (curr_sym->st_shndx == symbol->st_shndx
          && symbol->st_value == (Elf_Addr) curr_rela->r_addend) {
        (*num_rela)++;
        // Resize the array to fit another pointer
        rela = (Elf_Rela **) realloc(rela, *num_rela * sizeof(Elf_Rela *));
        // Put it at the new end of the array
        rela[*num_rela - 1] = curr_rela;
      }
    } else {
      if (ELF_R_SYM(curr_rela->r_info) == symbol_idx) {
        (*num_rela)++;
        // Resize the array to fit another pointer
        rela = (Elf_Rela **) realloc(rela, *num_rela * sizeof(Elf_Rela *));
        // Put it at the new end of the array
        rela[*num_rela - 1] = curr_rela;
      }
    }
  }
  error: return rela;
}

// Patches all occurences of a relocation inside a specific symbol with a hook.
//
// Args:
//  obj: ELF object to operate on.
//  sym_name: symbol name of the symbol to search for.
//  rel_sym_name: symbol name relocated into the symbol.
//  hook_sym_name: symbol to hook into rela.
//
// Returns: ELF_SUCCESS if a relocation was found, ELF_ERR otherwise.
//
ELF_ERROR elf_patch_all_rela_to_sym(ELF_OBJ *obj, char *sym_name,
    char *rel_sym_name, char *hook_sym_name) {
  Elf_Shdr *curr_section;
  Elf_Ehdr *ehdr;
  Elf_Sym *sym, *rel_sym, *hook_sym;
  Elf_Word sym_idx, rel_sym_idx, hook_sym_idx;
  Elf_Rela **rela;
  Elf_Word num_rela;

  if (elf_get_symbol_by_name(obj, sym_name, &sym, &sym_idx)) {
    log_print(LL_ERR, "Can't locate symbol %s in object", sym_name);
    return ELF_FAILURE;
  }
  if (elf_get_symbol_by_name(obj, rel_sym_name, &rel_sym, &rel_sym_idx)) {
    log_print(LL_ERR, "Can't locate symbol %s in object", rel_sym_name);
    return ELF_FAILURE;
  }
  if (elf_get_symbol_by_name(obj, hook_sym_name, &hook_sym, &hook_sym_idx)) {
    log_print(LL_ERR, "Can't locate symbol %s in object", rel_sym_name);
    return ELF_FAILURE;
  }
  if (obj->get_ehdr(obj, &ehdr) != ELF_SUCCESS) {
    log_print(LL_ERR, "Failed to patch rela to sym %s, ehdr not found",
        sym_name);
    return ELF_FAILURE;
  }
  for (size_t idx = 0; idx < ehdr->e_shnum; idx++) {
    if (elf_get_section(obj, idx, &curr_section)) {
      log_print(LL_ERR, "Invalid section header entry %d, skipping...", idx);
      continue;
    }
    switch (curr_section->sh_type) {
      case SHT_REL:
        log_print(LL_ERR, "Skipping section %d, "
                  "SHT_REL relocations not supported yet",
                  idx);
        continue;
        break;

      case SHT_RELA:
        // We only need to check relocation entries for the section containing
        // the symbol.
        if (curr_section->sh_info != sym->st_shndx) {
          continue;
        }
        if (!(rela = elf_find_all_rela_in_sec(obj, curr_section, rel_sym_idx,
                                              &num_rela))) {
          // The section has no rela at all to this symbol, skip
          continue;
        } else {
          // Now check if any of the rela found point into the symbol
          for (size_t rel_idx = 0; rel_idx < num_rela; rel_idx++) {
            if ((rela[rel_idx]->r_offset >= sym->st_value)
                && (rela[rel_idx]->r_offset < (sym->st_value + sym->st_size))) {
              log_print(LL_DBG, "replacing relocation at offset %08x for "
                        "symbol %d with %s (%d)",
                        rela[rel_idx]->r_offset, sym_idx, hook_sym_name,
                        hook_sym_idx);
              // Set the new symbol and make it an absolute relocation,
              // as we always hook absolute
              rela[rel_idx]->r_info = ELF_R_INFO(hook_sym_idx, ELF_R_ABS);
              // Only section relative relocations need the addend,
              // but we always hook absolute, so remove the addend.
              rela[rel_idx]->r_addend = 0;
            }
          }
        }
        break;
    }
  }
  free(rela);
  return ELF_SUCCESS;
}

// Finds out if an object has a relocation of a specific symbol into another
// symbol. E.g. if there is a relocation for a function into a struct.
//
// Args:
//  obj: ELF object to operate on.
//  sym_name: symbol name of the symbol to search for.
//  rel_sym_name: symbol name relocated into the symbol.
//
// Returns: ELF_SUCCESS if a relocation was found, ELF_ERR otherwise.
//
ELF_ERROR elf_has_rela_to_sym(ELF_OBJ *obj, const char *sym_name,
    const char *rel_sym_name) {
  Elf_Shdr *curr_section;
  Elf_Ehdr *ehdr;
  Elf_Sym *sym, *rel_sym;
  Elf_Word sym_idx, rel_sym_idx;
  Elf_Rela **rela;
  Elf_Word num_rela;

  if (elf_get_symbol_by_suffix(obj, sym_name, &sym, &sym_idx)) {
    log_print(LL_ERR, "Can't locate symbol %s in object", sym_name);
    return ELF_FAILURE;
  }
  if (elf_get_symbol_by_suffix(obj, rel_sym_name, &rel_sym, &rel_sym_idx)) {
    log_print(LL_ERR, "Can't locate symbol %s in object", rel_sym_name);
    return ELF_FAILURE;
  }
  if (obj->get_ehdr(obj, &ehdr) != ELF_SUCCESS) {
    log_print(LL_ERR, "Failed to patch rela to sym %s, ehdr not found",
        sym_name);
    return ELF_FAILURE;
  }
  for (size_t idx = 0; idx < ehdr->e_shnum; idx++) {
    if (elf_get_section(obj, idx, &curr_section)) {
      log_print(LL_ERR, "Invalid section header entry %d, skipping...", idx);
      continue;
    }
    switch (curr_section->sh_type) {
      case SHT_REL:
        log_print(LL_ERR, "Skipping section %d, "
                  "SHT_REL relocations not supported yet",
                  idx);
        continue;
        break;

      case SHT_RELA:
        // We only need to check relocation entries for the section containing
        // the symbol.
        if (curr_section->sh_info != sym->st_shndx) {
          continue;
        }
        if (!(rela = elf_find_all_rela_in_sec(obj, curr_section, rel_sym_idx,
                                              &num_rela))) {
          // The section has no rela at all to this symbol, skip
          continue;
        } else {
          // Now check if any of the rela found point into the symbol
          for (size_t rel_idx = 0; rel_idx < num_rela; rel_idx++) {
            if ((rela[rel_idx]->r_offset >= sym->st_value)
                && (rela[rel_idx]->r_offset < (sym->st_value + sym->st_size))) {
              free(rela);
              return ELF_SUCCESS;
            }
          }
        }
        break;
    }
  }
  // If we get to here without exiting we didn't find anything.
  return ELF_FAILURE;
}
