// These functions simplify the relinking of ELF relocatable object files.
// They require the file to be copied into memory,
// which simplifies error handling.
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
#include <stdio.h>

#include "elfrelink.h"
#include "../log/log.h"

// Replace a symbol value in .symtab with another one, effectively hooking
// calls to this symbol.
ELF_ERROR elf_hook_symbol(ELF_OBJ *obj, char *symbol_name, char *hook_name) {
  Elf_Sym *symbol, *hook;
  Elf_Word idx;

  if (obj->symbol_by_name(obj, symbol_name, &symbol, &idx)) {
    log_print(LL_ERR, "Symbol %s does not exist, aborting...", symbol_name);
    return ELF_FAILURE;
  } else {
    log_print(LL_DBG, "Found symbol %s (%d)", symbol_name, idx);
  }
  if (obj->symbol_by_name(obj, hook_name, &hook, &idx)) {
    log_print(LL_ERR, "Hook symbol %s does not exist, aborting...", hook_name);
    return ELF_FAILURE;
  } else {
    log_print(LL_DBG, "Found hook symbol %s (%d)", hook_name, idx);
  }
  log_print(LL_LOG, "Patching %s (%#08x) to %#08x", symbol_name,
            symbol->st_value, hook->st_value);

  symbol->st_value = hook->st_value;
  return ELF_SUCCESS;
}

// Performs all relocation hooks for relocations for a section.
//
// Args:
//  obj: Pointer to the elf file object
//  rel_section: Pointer to the section header for this section
//  symbol_idx: symtab index for the symbol to hook
//  hook_name: name of the hook symbol to insert into the relocations
//  target_offset: Offset of the relocation. If this is 0 nothing will change,
//    if not the relocation will point at another address in the code.
//
ELF_ERROR elf_hook_rela(ELF_OBJ *obj, Elf_Shdr *rel_section,
    Elf_Word symbol_idx, char *hook_name, Elf_Word target_offset) {
  Elf_Rela **rela;
  Elf_Word num_rela;
  char *rel_section_name;
  Elf_Sym *hook;
  Elf_Word hook_idx;

  if (!obj->section_get_name(obj, rel_section, &rel_section_name)) {
    log_print(LL_DBG, "Scanning relocations for symbol %d in section %s",
              symbol_idx, rel_section_name);
  }
  // No hook means we delete, so it's still ok
  if (hook_name != NULL) {
    if (obj->symbol_by_name(obj, hook_name, &hook, &hook_idx)) {
      // An invalid hook should still throw an error, though
      log_print(LL_ERR, "Hook symbol %s does not exist, aborting...",
                hook_name);
      return ELF_FAILURE;
    }
  }
  rela = obj->relocation_by_symbol(obj, rel_section, symbol_idx, &num_rela);
  if (!rela) {
    log_print(LL_DBG, "No relocations to symbol %d in section %s", symbol_idx,
              rel_section_name);
    // No relocations still means success, we don't have to patch
    return ELF_SUCCESS;
  }
  log_print(LL_DBG, "Found %d relocations for symbol %d", num_rela, symbol_idx);
  for (Elf_Word i = 0; i < num_rela; i++) {
    if (hook_name == NULL) {
      log_print(LL_DBG, "disabling relocation for offset %08x",
                rela[i]->r_offset);
      rela[i]->r_info = ELF_R_INFO(ELF_R_SYM(rela[i]->r_info), ELF_R_NONE);
    } else {
      log_print(LL_DBG, "replacing relocation at offset %08x for "
                "symbol %d with %s (%d)",
                rela[i]->r_offset, symbol_idx, hook_name, hook_idx);
      // Set the new symbol and make it an absolute relocation,
      // as we always hook absolute
      rela[i]->r_info = ELF_R_INFO(hook_idx, ELF_R_ABS);
      // Only section relative relocations need the addend, but we always hook
      // absolute, so remove the addend.
      rela[i]->r_addend = 0;
      if (target_offset) {
        log_print(LL_LOG, "changing rela offset from %08x to %08x",
                  rela[i]->r_offset, target_offset);
        rela[i]->r_offset = target_offset;
      }
    }
  }
  free(rela);
  return ELF_SUCCESS;
}

// Changes all relocation entries referencing a specific symbol to
// reference another symbol, effectively hooking code and data references.
//
// Args:
//  obj: Pointer to the elf file object
//  symbol_name: symbol name of the symbol to hook
//  hook_name: symbol name of the hook symbol to replace the original
//  target_offset: Offset of the relocation. If this is 0 nothing will change,
//    if not the relocation will point at another address in the code
//
ELF_ERROR elf_hook_all_relocations(ELF_OBJ *obj, char *symbol_name,
    char *hook_name, Elf_Word target_offset) {
  Elf_Ehdr *ehdr;
  Elf_Shdr *curr_section;
  Elf_Sym *target_symbol;
  Elf_Word target_idx;

  if (obj->get_ehdr(obj, &ehdr) != ELF_SUCCESS) {
    log_print(LL_ERR, "Can't hook relocations for %s, ehdr not found",
        symbol_name);
    return ELF_FAILURE;
  }
  if (obj->symbol_by_name(obj, symbol_name, &target_symbol, &target_idx)) {
    log_print(LL_ERR, "Symbol %s does not exist, aborting...", symbol_name);
    return ELF_FAILURE;
  }
  log_print(LL_DBG, "Found symbol %s at symtab index %d", symbol_name,
      target_idx);
  for (size_t idx = 0; idx < ehdr->e_shnum; idx++) {
    if (obj->section_by_idx(obj, idx, &curr_section)) {
      log_print(LL_ERR, "Invalid section header entry %d, skipping...", idx);
      continue;
    }
    switch (curr_section->sh_type) {
      case SHT_REL:
        // Only relevant for 32 bit, skip for now.
        log_print(LL_ERR, "Skipping section %d, "
                  "SHT_REL relocation hooking not supported yet",
                  idx);
        continue;
        break;

      case SHT_RELA:
        elf_hook_rela(obj, curr_section, target_idx, hook_name, target_offset);
        break;
    }
  }
  return ELF_SUCCESS;
}

// Copy all symtab entries that reference symbols in section number 'src_idx' to
// to the symtab in 'dest_obj'. Also copy the names into 'dest_obj' strtab and
// fix all references in 'dest_obj'
//
// Args:
//  src_obj: Pointer to the elf obj to copy from
//  dest_obj: Pointer to the target elf obj
//  src_idx: Index of the section in src_obj whose symbols to copy
//  dest_idx: Index of this section in the target obj
//
// Returns: ELF_SUCCESS or ELF_ERROR on failure.
//
ELF_ERROR elf_migrate_symbols(ELF_OBJ *src_obj, ELF_OBJ *dest_obj,
    Elf_Word src_idx, Elf_Word dest_idx) {
  Elf_Sym *src_sym, *dst_sym;
  Elf_Word dst_sym_idx, dst_sym_name;
  char *src_name;
  Elf_Shdr *symtab, *strtab;
  Elf_Word symtab_idx, strtab_idx;

  if (src_obj->section_by_name(src_obj, ".symtab", &symtab_idx, &symtab)
      != ELF_SUCCESS) {
    log_print(LL_ERR, "Can't migrate symbols, symtab not found");
    return ELF_FAILURE;
  }
  Elf_Word num_syms = symtab->sh_size / symtab->sh_entsize;

  log_print(LL_DBG, "Migrating all symbols for section %d to destination (%d)",
            src_idx, dest_idx);

  for (Elf_Word i = 0; i < num_syms; i++) {
    if (src_obj->symbol_by_idx(src_obj, i, &src_sym) != ELF_SUCCESS) {
      log_print(LL_ERR, "Couldn't find symbol %d, skipping", i);
      continue;
    }
    if (src_sym->st_name == 0) {
      continue;
    }
    if (src_obj->symbol_get_name(src_obj, src_sym->st_name, &src_name)
        != ELF_SUCCESS) {
      log_print(LL_ERR, "Symbol %d name out of range, skipping", i);
      continue;
    }
    if (src_sym->st_shndx == src_idx) {
      log_print(LL_DBG, "Symbol %s references section %d in source object, "
                "migrating to destination object",
                src_name, src_sym->st_shndx);
      if (dest_obj->section_by_name(dest_obj, ".strtab", &strtab_idx, &strtab)
          != ELF_SUCCESS) {
        log_print(LL_ERR, "Can't migrate symbols, .strtab not found");
        return ELF_FAILURE;
      }
      if (elf_add_strtab_entry(dest_obj, strtab_idx, src_name,
                               &dst_sym_name) != ELF_SUCCESS) {
        log_print(LL_ERR, "Failed to insert name of symbol %s into dest obj",
                  src_name);
        return ELF_FAILURE;
      }
      log_print(LL_DBG, "Added strtab idx %d to dest obj", dst_sym_name);
      if (elf_add_symtab_entry(dest_obj, src_sym, &dst_sym_idx)
          != ELF_SUCCESS) {
        log_print(LL_ERR, "Failed to copy symbol %d to destination object", i);
        return ELF_FAILURE;
      }
      if (dest_obj->symbol_by_idx(dest_obj, dst_sym_idx, &dst_sym)
          != ELF_SUCCESS) {
        log_print(LL_ERR, "Couldn't find symbol that was just inserted (%d)",
            dest_idx);
        return ELF_FAILURE;
      }
      // Fix the name reference
      log_print(LL_DBG, "Inserted strtab entry %d", dst_sym_name);
      dst_sym->st_name = dst_sym_name;
      // Now fix the section reference
      if (dest_obj->symbol_by_idx(dest_obj, dst_sym_idx, &dst_sym)
          != ELF_SUCCESS) {
        log_print(LL_ERR, "Failed to get symbol %d in destination object", i);
        return ELF_FAILURE;
      }
      dst_sym->st_shndx = dest_idx;
    }
  }
  return ELF_SUCCESS;
}

// Migrate a relocation section from one module to another.
// Fix up all references to sections and symbols to adjust to target.
ELF_ERROR elf_migrate_rela(ELF_OBJ *src, ELF_OBJ *dst, Elf_Word rela_idx,
    Elf_Word sec_idx, Elf_Word dst_sec_idx, char *prefix) {
  Elf_Shdr *shdr, *rela, *dst_rela, *dst_symtab, *rela_sec, *rela_sec_dst;
  Elf_Sym *sym, *rela_sym;
  Elf_Rela *curr_rela;
  Elf_Word dst_rela_idx, dst_symtab_idx, sym_idx, rela_sec_idx,
      rela_sec_dst_idx;
  char *name, *sym_name, *rela_sec_name;
  uint8_t *rela_contents;

  if (src->section_by_idx(src, sec_idx, &shdr) != ELF_SUCCESS) {
    log_print(LL_ERR, "Can't find source section %d for rela migration",
        sec_idx);
    return ELF_FAILURE;
  }
  if (src->section_by_idx(src, rela_idx, &rela) != ELF_SUCCESS) {
    log_print(LL_ERR, "Can't find rela section %d for rela migration",
        rela_idx);
    return ELF_FAILURE;
  }
  if (src->section_get_name(src, rela, &name) != ELF_SUCCESS) {
    log_print(LL_ERR, "Can't get name for rela section %d", rela_idx);
    return ELF_FAILURE;
  }
  if (src->section_get_contents(src, rela, &rela_contents) != ELF_SUCCESS) {
    log_print(LL_ERR, "Can't get contents of rela section %d", rela_idx);
    return ELF_FAILURE;
  }
  if (elf_inject_section(dst, src, rela_contents, rela->sh_size, rela, rela_idx,
        name, &dst_rela_idx) != ELF_SUCCESS) {
    log_print(LL_ERR, "Can't inject rela section %d into target", rela_idx);
    return ELF_FAILURE;
  }
  if (dst->section_by_idx(dst, dst_rela_idx, &dst_rela) != ELF_SUCCESS) {
    log_print(LL_ERR, "Can't find copied rela section %d", sec_idx);
    return ELF_FAILURE;
  }
  if (dst->section_by_name(dst, ".symtab", &dst_symtab_idx, &dst_symtab)
      != ELF_SUCCESS) {
    log_print(LL_ERR, "Can't find symtab in dst");
    return ELF_FAILURE;
  }
  // Update the symtab and section number to match new obj
  dst_rela->sh_info = dst_sec_idx;
  dst_rela->sh_link = dst_symtab_idx;
  // Update symtab references to match the new one in host
  for (size_t i = 0; i < dst_rela->sh_size / dst_rela->sh_entsize; i++) {
    curr_rela = (Elf_Rela *)
      (dst->data + (dst_rela->sh_offset + (i * sizeof(Elf_Rela))));
    if (elf_ptr_invalid(dst, (uint8_t *) curr_rela) != ELF_SUCCESS) {
      log_print(LL_ERR, "Failed to fix up injected rela, ptr invalid");
      return ELF_FAILURE;
    }
    if (src->symbol_by_idx(src, ELF_R_SYM(curr_rela->r_info), &rela_sym)
        != ELF_SUCCESS) {
      log_print(LL_ERR, "Failed to find symbol %d in rela %d for sec %d",
          ELF_R_SYM(curr_rela->r_info), i, sec_idx);
      return ELF_FAILURE;
    }
    // Lookup the symbol reference in the source object
    if (src->symbol_get_name(src, rela_sym->st_name, &sym_name)
        != ELF_SUCCESS) {
      log_print(LL_ERR, "Failed to find associated symbol %d for rela %d "
          "in rela for sec %d", ELF_R_SYM(curr_rela->r_info), i, sec_idx);
      return ELF_FAILURE;
    }
    log_print(LL_DBG, "Found symbol %s referenced in rela %d for sec %d",
          sym_name, i, sec_idx);
    // Check if its a section relative relocation as section symbols are unnamed
    // and need to be looked up in the section headers instead of the symbol
    // table.
    if (ELF_ST_TYPE(rela_sym->st_info) == STT_SECTION) {
      rela_sec_idx = rela_sym->st_shndx;
      log_print(LL_DBG, "Rela %d refers to section %d, migrating by "
          "section headers", rela_sec_idx, i);
      if (src->section_by_idx(src, rela_sec_idx, &rela_sec) != ELF_SUCCESS) {
        log_print(LL_ERR, "Failed to find section %d referenced in rela %d",
            rela_sym->st_value, i);
        return ELF_FAILURE;
      }
      if (src->section_get_name(src, rela_sec, &rela_sec_name) != ELF_SUCCESS) {
        log_print(LL_ERR, "Failed to get name for section %d referenced "
            "in rela %d", rela_sym->st_value, i);
        return ELF_FAILURE;
      }
      // generate the prefixed version of this section name
      // (duplicate section names get prefixed on injection,
      // we need to search for that first)
      char *prefixed_name = NULL;
      size_t prefix_len = strlen(prefix);
      size_t prefixed_name_len = strlen(rela_sec_name) + prefix_len + 1;
      if ((prefixed_name = (char *) malloc(prefixed_name_len * sizeof(char)))
          == NULL) {
        log_print(LL_ERR, "Couldn't allocate memory for new section name");
        return ELF_FAILURE;
      }
      strncpy(prefixed_name, prefix, strlen(prefix));
      strncpy(prefixed_name + strlen(prefix), rela_sec_name,
              strlen(rela_sec_name));
      prefixed_name[prefixed_name_len - 1] = 0x00;
      // Now search for a prefixed section first
      if (dst->section_by_name(dst, prefixed_name, &rela_sec_dst_idx,
            &rela_sec_dst) != ELF_SUCCESS) {
        // If there is none, maybe it was injected without a prefix
        if (dst->section_by_name(dst, rela_sec_name, &rela_sec_dst_idx,
              &rela_sec_dst) != ELF_SUCCESS) {
          log_print(LL_ERR, "Failed to find section %s in destination object",
              rela_sec_name);
          free(prefixed_name);
          return ELF_FAILURE;
        }
      }
      free(prefixed_name);
      // Finally find the symbol that points to rela_sec_dst_idx section
      // (it might have a .pmem prefix)
      if (dst->symbol_to_section(dst, rela_sec_dst_idx, &sym, &sym_idx)
          != ELF_SUCCESS) {
        log_print(LL_ERR, "Failed to find symbol referring to section %s "
            "for rela %d for sec %d in destination object", rela_sec_name, i,
            sec_idx);
        return ELF_FAILURE;
      }
      // if its not section relative there is a named symtab entry
      // which we can look up.
    } else {
      log_print(LL_DBG, "Rela %d refers to symbol, migrating by symbol table",
          i);
      // Find symbol index for this symbol in destination object
      if (dst->symbol_by_name(dst, sym_name, &sym, &sym_idx)
          != ELF_SUCCESS) {
        log_print(LL_ERR, "Failed to find symbol %s for rela %d for sec %d "
            "in destination object", sym_name, i, sec_idx);
        return ELF_FAILURE;
      }
    }
    // Fix up rela symbol index with correct target index
    curr_rela->r_info = (ELF_R_INFO(sym_idx, ELF_R_TYPE(curr_rela->r_info)));
  }
  return ELF_SUCCESS;
}

// Injects a section name into the shstrtab of an elf object.
// If there already is a section with this name in the target, it will prefix
// the name. It will be copied to a caller allocated buffer if large enough.
//
// Args:
//  dst: Pointer to the elf object to inject into
//  name: Desired name of the section
//  prefix: String to prefix a name with if already exists under this name.
//  new_name: Caller allocated buffer that will hold the new name
//  new_name_size: Size of the caller allocated buffer
//  shstrtab_off: Pointer to an Elf_Word where the offset of the copied name
//    in the shstrtab will be stored.
//
ELF_ERROR elf_inject_section_name(ELF_OBJ *dst, char *name,
    char *prefix, char *new_name, size_t new_name_size,
    Elf_Word *shstrtab_off) {
  Elf_Shdr *tmp_section = NULL, *shstrtab = NULL;
  Elf_Word tmp_section_idx = 0, shstrtab_idx = 0;
  size_t name_len = strlen(name);
  size_t prefix_len = strlen(prefix);

  // If a section with this name already exists, prefix it
  if (dst->section_by_name(dst, name, &tmp_section_idx, &tmp_section)
      == ELF_SUCCESS) {
    if ((name_len + prefix_len + 1) <= new_name_size) {
      strncpy(new_name, prefix, prefix_len);
      strncpy(new_name + prefix_len, name, name_len + 1);
      log_print(LL_DBG, "Section %s already exists, renaming to %s", name,
          new_name);
    } else {
      log_print(LL_ERR, "Can't rename section %s, name buffer is too small",
          name);
      return ELF_FAILURE;
    }
  } else {
    log_print(LL_DBG, "Section %s does not exist in target, injecting...",
        name);
    if ((name_len + 1) <= new_name_size) {
      strncpy(new_name, name, name_len + 1);
    } else {
      log_print(LL_ERR, "Can't copy section name %s, name buffer is too small",
          name);
      return ELF_FAILURE;
    }
  }
  // Make sure the name is always \0 terminated
  new_name[new_name_size - 1] = 0x00;
  // Now go ahead and inject it into .shstrtab
  if (dst->get_shstrtab(dst, &shstrtab, &shstrtab_idx)
      != ELF_SUCCESS) {
    log_print(LL_ERR, "Can't inject section name %s, .shstrtab not found",
        name);
    return ELF_FAILURE;
  }
  log_print(LL_DBG, "Adding shstrtab entry (shstrtab at %d of size %d)",
            shstrtab->sh_offset, shstrtab->sh_size);
  if (elf_add_strtab_entry(dst, shstrtab_idx, new_name, shstrtab_off)) {
    log_print(LL_ERR, "Couldn't insert section name %s into shstrtab", name);
    return ELF_FAILURE;
  }
  return ELF_SUCCESS;
}

// Injects an in-memory buffer into an elf file as a new section.
// Will create a new section header, shstrtab entry, move the section headers
// back, insert the section between the last one and the section header
// table and insert a new symbol refering to the new section.
// If the section header table is not at the end of the file it will copy
// it to the end and change the ehdr->e_shoff entry.
//
// Args:
//  obj: Pointer to the elf file obj to inject into
//  src: Pointer to the elf file obj to copy from
//  section: Pointer to a buffer containing the new sections data
//  len: size of section in bytes
//  section_shdr: Pointer to the section header for the new section
//  section_idx: Index of the section in the shdr table
//  name: name of the section as it will be inserted into shstrtab
//  name_len: size of the name buffer including the 0x00 byte
//
// Returns: ELF_SUCCESS or ELF_ERROR on failure
//
ELF_ERROR elf_inject_section(ELF_OBJ *obj, ELF_OBJ *src, uint8_t const *section,
    size_t len, Elf_Shdr *section_shdr, Elf_Word section_idx, char *name,
    Elf_Word *new_shdr_idx) {
  Elf_Shdr *injected_section;
  Elf_Sym *sec_sym, *sec_dst_sym;
  Elf_Word sec_sym_idx;
  uint8_t *new_section;
  Elf_Word new_section_off;
  Elf_Word shdrstrtab_entry_off;
  char actual_name[BUFSIZ];
  char *prefix = ".pmem";

  if (strlen(name) > 0) {
    if (elf_inject_section_name(obj, name, prefix, actual_name,
          sizeof(actual_name), &shdrstrtab_entry_off) != ELF_SUCCESS) {
      log_print(LL_ERR, "Can't inject section %s, unable to create name in "
          "target object", name);
      return ELF_FAILURE;
    }
  } else {
    log_print(LL_DBG, "Name is empty, no new name in shstrtab needed");
    // If no name is specified use the empty name at the beginning of shstrtab
    shdrstrtab_entry_off = 0;
  }
  log_print(LL_DBG, "Injecting section %s into target object", actual_name);
  // Create the new shdr entry. The section offset is 0 initially,
  // to prevent any symbol/string injection to shift the section when it's not
  // there yet.
  if (elf_add_shdr(obj, section_shdr, shdrstrtab_entry_off, 0, new_shdr_idx)) {
    log_print(LL_ERR, "Failed to inject section %s, unable to add shdr in "
        "target object", name);
    return ELF_FAILURE;
  }
  // Add a symtab entry so rela can reference it, if one existed before
  if (src->symbol_to_section(src, section_idx, &sec_sym, &sec_sym_idx)
      == ELF_SUCCESS) {
    if (elf_add_symtab_entry(obj, sec_sym, &sec_sym_idx) != ELF_SUCCESS) {
      log_print(LL_ERR, "Couldn't insert symtab entry for injected section %s",
                name);
      return ELF_FAILURE;
    }
    // Fixup the section reference in the copied symbol
    if (obj->symbol_by_idx(obj, sec_sym_idx, &sec_dst_sym) != ELF_SUCCESS) {
      log_print(LL_ERR, "Can't find symbol that was just inserted (%d)",
          sec_sym_idx);
      return ELF_FAILURE;
    }
    sec_dst_sym->st_shndx = *new_shdr_idx;
    // Make the symbol global so we don't have to reorder the symbol table
    sec_dst_sym->st_info =
      ELF_ST_INFO(STB_GLOBAL, ELF_ST_TYPE(sec_dst_sym->st_info));
  }
  // Add the section itself
  new_section_off = obj->size;
  if (elf_enlarge_obj(obj, len) != ELF_SUCCESS) {
    log_print(LL_ERR, "Couldn't enlarge elf object to fit new section");
    return ELF_FAILURE;
  }
  log_print(LL_DBG, "Injecting section %s to offset 0x%08x of elf object",
            actual_name, new_section_off);
  new_section = obj->data + new_section_off;
  if (elf_ptr_invalid(obj, new_section)) {
    log_print(LL_ERR, "New section offset %d outside file", new_section_off);
    return ELF_FAILURE;
  }
  log_print(LL_DBG, "Copying new section into elf object");
  memcpy(new_section, section, len);
  // Finally fix up the section reference in the Shdr
  if (obj->section_by_idx(obj, *new_shdr_idx, &injected_section)
      != ELF_SUCCESS) {
    log_print(LL_ERR, "Can't find shdr for injected section");
    return ELF_FAILURE;
  }
  injected_section->sh_offset = new_section_off;
  return ELF_SUCCESS;
}

// Inject all sections of one elf object into another. Copies the relevant
// section headers and also fixes up all offsets in the symbol table and the
// section numbers in the relocation tables.
ELF_ERROR elf_inject_obj(ELF_OBJ *host, ELF_OBJ *parasite,
    char *parasite_name) {
  Elf_Ehdr *parasite_ehdr;
  char full_section_name[BUFSIZ];
  Elf_Shdr *source_section, *rela_section, *migrated_section, *bss, *dst_bss;
  size_t num_injected_sections = 0;
  uint8_t *source_data;
  size_t source_len;
  char *source_name;
  Elf_Word section_idx, rela_idx, migrated_section_idx, bss_idx, dst_bss_idx;

  if (host->get_ehdr(parasite, &parasite_ehdr) != ELF_SUCCESS) {
      log_print(LL_DBG, "section is not last in file, pushing next one back");
    log_print(LL_ERR, "Can't inject object, ehdr missing");
    return ELF_FAILURE;
  }
  if (parasite->section_by_name(parasite, ".bss", &bss_idx, &bss)
      == ELF_SUCCESS) {
    if (host->section_by_name(host, ".bss", &dst_bss_idx, &dst_bss)
        != ELF_SUCCESS) {
      log_print(LL_ERR, "Target has no .bss, this is odd, aborting");
      return ELF_FAILURE;
    }
    // We don't want the original object to run, so just hijack it's .bss
    if (elf_enlarge_section(host, dst_bss_idx, bss->sh_size) != ELF_SUCCESS) {
      log_print(LL_ERR, "Can't enlarge target's bss, unable to inject object");
      return ELF_FAILURE;
    }
    // .bss is a special case since it doesn't really occupy space in the file:
    if (elf_migrate_symbols(parasite, host, bss_idx, dst_bss_idx)
        != ELF_SUCCESS) {
      log_print(LL_ERR, "Failed to migrate symbols from .bss to host");
      return ELF_FAILURE;
    }
  } else {
    log_print(LL_ERR, "object to inject has no .bss, this is rare, "
              "but possible so continuing without it...");
  }
  for (size_t i = 0; i < parasite_ehdr->e_shnum; i++) {
    if (parasite->section_by_idx(parasite, i, &source_section) != ELF_SUCCESS) {
      log_print(LL_ERR, "Failed to get section %d, skipping", i);
      continue;
    }
    if (parasite->section_get_name(parasite, source_section, &source_name)
        != ELF_SUCCESS) {
      log_print(LL_ERR, "Failed to get name for section %d, skipping", i);
      continue;
    }
    if (source_section->sh_type != SHT_PROGBITS) {
      log_print(LL_DBG, "Skipping section %s, only PROGBITS are injected",
          source_name);
      continue;
    }
    if (source_section->sh_size == 0) {
      log_print(LL_DBG, "Skipping section %s, has size NULL", source_name);
      continue;
    }
    if (parasite->section_get_contents(parasite, source_section, &source_data)
        != ELF_SUCCESS) {
      log_print(LL_ERR, "Failed to get contents of section %s, skipping",
          source_name);
      continue;
    }
    source_len = source_section->sh_size;
    log_print(LL_DBG, "Injecting contents of section %s", source_name);
    if (elf_inject_section(host, parasite, source_data, source_len,
                           source_section, i, source_name,
                           &section_idx) != ELF_SUCCESS) {
      log_print(LL_ERR, "Failed to inject section %s into host module",
                source_name);
      return ELF_FAILURE;
    }
    log_print(LL_DBG, "Migrating symbols of section %s", source_name);
    if (elf_migrate_symbols(parasite, host, i, section_idx) != ELF_SUCCESS) {
      log_print(LL_ERR, "Failed to migrate symbols of section %d to host", i);
      // For most things we were ok to just skip the section but if this goes
      // wrong the host will be in an inconsistent state and we can't continue.
      return ELF_FAILURE;
    }
    num_injected_sections++;
    log_print(LL_DBG, "Injected section %s into host", source_name);
  }
  log_print(LL_DBG, "Finished injection of PROGBITS, now injecting RELA");
  // We have to loop again because rela contain references to multiple other
  // sections and we can only migrate them after we finish the migration of all
  // sections and their symbols
  for (size_t i = 0; i < parasite_ehdr->e_shnum; i++) {
    if (parasite->section_by_idx(parasite, i, &source_section) != ELF_SUCCESS) {
      log_print(LL_ERR, "Failed to get section %d, skipping", i);
      continue;
    }
    if (source_section->sh_type != SHT_PROGBITS) {
      log_print(LL_DBG, "Skipping section %d, only PROGBITS are injected", i);
      continue;
    }
    if (source_section->sh_size == 0) {
      log_print(LL_DBG, "Skipping section %s, has size NULL", source_name);
      continue;
    }
    if (parasite->section_get_name(parasite, source_section, &source_name)
        != ELF_SUCCESS) {
      log_print(LL_ERR, "Failed to get name for section %d, skipping", i);
      continue;
    }
    // sections might get a prefix in target if name already exists,
    // so search by prefixed name first.
    if ((strlen(source_name) + strlen(parasite_name) + 1) > BUFSIZ) {
      log_print(LL_ERR, "Can't merge relocations, names overflow buffer");
      return ELF_FAILURE;
    }
    // prefix section name with parasite name (eg. pmem.text)
    strncpy(full_section_name, parasite_name, BUFSIZ);
    strncat(full_section_name, source_name, BUFSIZ - strlen(full_section_name));
    if (host->section_by_name(host, full_section_name, &migrated_section_idx,
                                &migrated_section) != ELF_SUCCESS) {
      if (host->section_by_name(host, source_name, &migrated_section_idx,
            &migrated_section) != ELF_SUCCESS) {
        log_print(LL_ERR, "Couldn't find corresponding section in target "
            "for section %s", source_name);
        return ELF_FAILURE;
      }
    }
    // Finally migrate the corresponding rela section (if any). Will also fix
    // any symbol and section references in the rela.
    if (parasite->relocation_to_section(parasite, i, &rela_section, &rela_idx)
        == ELF_SUCCESS) {
      log_print(LL_DBG, "Migrating relocation section %d for section %d",
                rela_idx, i);
      if (elf_migrate_rela(parasite, host, rela_idx, i, migrated_section_idx,
                           parasite_name) != ELF_SUCCESS) {
        log_print(LL_ERR, "Failed to migrate relocations");
        return ELF_FAILURE;
      }
      log_print(LL_DBG, "Merged relocations for section %d", i);
    } else {
      log_print(LL_DBG, "Section %d has no relocations, no need to migrate", i);
    }
  }
  if (num_injected_sections > 0) {
    log_print(LL_DBG, "Injected %d sections into host module",
              num_injected_sections);
    return ELF_SUCCESS;
  }
  return ELF_FAILURE;
}


