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

#include <string.h>

#include "elf_object.h"
#include "elf_sections.h"
#include "../log/log.h"


// Parses the section headers and returns a specific section.
ELF_ERROR elf_get_section(ELF_OBJ *obj, Elf_Word idx, Elf_Shdr **section) {
  Elf_Ehdr *ehdr;

  if (obj->get_ehdr(obj, &ehdr) != ELF_SUCCESS) {
    log_print(LL_ERR, "Can't get section %d, ehdr not found", idx);
    return ELF_FAILURE;
  }
  *section = (Elf_Shdr *) (obj->data + ehdr->e_shoff
      + idx * ehdr->e_shentsize);
  if (elf_ptr_invalid(obj, (uint8_t *) *section)) {
    log_print(LL_DBG, "Can't find section %d", idx);
    return ELF_FAILURE;
  }
  return ELF_SUCCESS;
}

// Parses the section headers string table and point 'name' to the name of a
// specific section.
ELF_ERROR elf_get_section_name(ELF_OBJ *obj, Elf_Shdr *section, char **name) {
  Elf_Shdr *shstrtab = NULL;
  Elf_Word shstrtab_idx = 0;

  if (obj->get_shstrtab(obj, &shstrtab, &shstrtab_idx) != ELF_SUCCESS) {
    log_print(LL_ERR, "Can't get section name, shstrtab not found");
    return ELF_FAILURE;
  }
  *name = (char *) (obj->data + (shstrtab->sh_offset + section->sh_name));
  if (elf_ptr_invalid(obj, (uint8_t *) *name)) {
    log_print(LL_ERR, "Can't get section name, offset of shstrtab (%#08x)"
              "or sh_name offset (%#08x) are wrong",
              shstrtab->sh_offset, section->sh_name);
    return ELF_FAILURE;
  }
  return ELF_SUCCESS;
}

// Parse the section table and find a specific section by name.
ELF_ERROR elf_get_section_by_name(ELF_OBJ *obj, char const *name,
    Elf_Word *idx, Elf_Shdr **section) {
  char *curr_name;
  Elf_Ehdr *ehdr;

  if (strlen(name) == 0) {
    log_print(LL_ERR, "Can't get section by name if name is empty!");
    return ELF_FAILURE;
  }
  if (obj->get_ehdr(obj, &ehdr) != ELF_SUCCESS) {
    log_print(LL_ERR, "Can't get section %s, elf headers not found", name);
    return ELF_FAILURE;
  }
  for (*idx = 0; *idx < ehdr->e_shnum; (*idx)++) {
    if (elf_get_section(obj, *idx, section)) {
      log_print(LL_DBG, "Invalid section header %d, skipping", *idx);
      continue;
    }
    if (elf_get_section_name(obj, *section, &curr_name) != ELF_SUCCESS) {
      log_print(LL_ERR, "Can't find section %s, get_section_name failed", name);
      return ELF_FAILURE;
    }
    if (!strcmp(curr_name, name)) {
      return ELF_SUCCESS;
    }
  }
  log_print(LL_DBG, "Can't find section %s", name);
  return ELF_FAILURE;
}

// Parse the section table and find a specific section by suffix.
ELF_ERROR elf_get_section_by_suffix(ELF_OBJ *obj, char const *name,
    Elf_Word *idx, Elf_Shdr **section) {
  char *curr_name;
  Elf_Ehdr *ehdr;

  if (obj->get_ehdr(obj, &ehdr) != ELF_SUCCESS) {
    log_print(LL_ERR, "Can't get section %s, elf headers not found", name);
    return ELF_FAILURE;
  }
  for (*idx = 0; *idx < ehdr->e_shnum; (*idx)++) {
    if (elf_get_section(obj, *idx, section)) {
      log_print(LL_DBG, "Invalid section header %d, skipping", *idx);
      continue;
    }
    if (elf_get_section_name(obj, *section, &curr_name)) {
      // It's perfectly fine to have sections without name
      continue;
    }
    if (string_has_suffix(curr_name, name) == ELF_SUCCESS) {
      return ELF_SUCCESS;
    }
  }
  log_print(LL_ERR, "Can't find section %s", name);
  return ELF_FAILURE;
}

// Parse the section headers and gets the next section after a specific offset
// in the file.
//
// Returns: ELF_SUCCESS if a section was found, ELF_ERROR if not.
//
ELF_ERROR elf_get_section_after(ELF_OBJ *obj, Elf_Off offset,
    Elf_Shdr **section, Elf_Word *section_idx) {
  Elf_Shdr *tmp_section;
  Elf_Off curr_dist = 0;
  Elf_Off closest_off = obj->size;  // maximum possible distance for start
  Elf_Ehdr *ehdr;

  if (obj->get_ehdr(obj, &ehdr) != ELF_SUCCESS) {
    log_print(LL_ERR, "Can't get section after %08x, elf headers not found",
        offset);
    return ELF_FAILURE;
  }
  for (Elf_Word idx = 0; idx < ehdr->e_shnum; idx++) {
    if (elf_get_section(obj, idx, &tmp_section)) {
      log_print(LL_ERR, "Failed to get section %d", idx);
      return ELF_FAILURE;
    }
    if (tmp_section->sh_type == SHT_NOBITS) {
      // .bss has an entry and size, but refers to memory not filesize.
      // We need to ignore it as it can cause bugs if it overlays with other
      // sections.
      continue;
    }
    if (tmp_section->sh_offset > offset) {
      // the section is actually after the offset were looking at.
      // We don't need to look at sections that are in front of us.
      curr_dist = tmp_section->sh_offset - offset;
      if (curr_dist < closest_off) {
        // We found a section closer than the last one
        closest_off = curr_dist;
        *section = tmp_section;
        *section_idx = idx;
      }
    }
  }
  // We actually found something
  if (closest_off < obj->size) {
    return ELF_SUCCESS;
  }
  return ELF_FAILURE;
}

// Moves the given section back in the file, creating space to insert a new
// section. Works recursively, so any sections behind it are also moved. Make
// sure you pre-allocate memory for this by using an appropriate excess value in
// read_obj or read_obj_from_mem and call enlarge_obj before this.
ELF_ERROR elf_move_section_back(ELF_OBJ *obj, Elf_Word section_idx,
Elf_Off offset) {
  Elf_Shdr *section;
  Elf_Shdr *section_after;
  Elf_Word section_after_idx;
  uint8_t *section_contents, *new_section_contents;

  if (elf_get_section(obj, section_idx, &section)) {
    log_print(LL_ERR, "Cant get section %d", section_idx);
    return ELF_FAILURE;
  }
  // The section header table might be behind this section
  if (elf_shdrtab_is_next(obj, section->sh_offset) == ELF_SUCCESS) {
    if (elf_move_shtab_back(obj, offset) != ELF_SUCCESS) {
      log_print(LL_ERR, "Failed to move shdrtable back %d bytes", offset);
      return ELF_FAILURE;
    }
  } else {
    // There might be other sections behind it we also have to move
    if (elf_get_section_after(obj, section->sh_offset, &section_after,
                              &section_after_idx) == ELF_SUCCESS) {
      if (elf_move_section_back(obj, section_after_idx, offset)
          != ELF_SUCCESS) {
        log_print(LL_ERR, "Unable to move section %d back %d bytes, aborting",
                  section_after_idx, offset);
        return ELF_FAILURE;
      }
    }
  }
  // Since we might have just moved the shdrs we must update the pointer
  if (elf_get_section(obj, section_idx, &section)) {
    log_print(LL_ERR, "Cant get section %d", section_idx);
    return ELF_FAILURE;
  }
  if (section->sh_offset + offset + section->sh_size > obj->size) {
    log_print(LL_ERR, "Can't move section %d (size %08x) from %08x to %08x, "
              "file ends at %08x",
              section_idx, section->sh_size, section->sh_offset,
              section->sh_offset + offset, obj->size);
    return ELF_FAILURE;
  }
  if (elf_get_section_contents(obj, section, &section_contents)) {
    log_print(LL_ERR, "Can't move section %d, can't get contents", section_idx);
    return ELF_FAILURE;
  }
  new_section_contents = section_contents + offset;
  if (elf_ptr_invalid(obj, new_section_contents) != ELF_SUCCESS) {
    log_print(LL_ERR, "Can't move section, new buffer out of file scope (%08x",
              new_section_contents);
    return ELF_FAILURE;
  }
  memmove(new_section_contents, section_contents, section->sh_size);
  section->sh_offset += offset;
  // Could have moved a section that has a pointer cached in obj so refresh
  if (elf_parse_headers(obj) != ELF_SUCCESS) {
    log_print(LL_ERR, "Something went wrong enlarging section at %d",
              section->sh_offset);
    return ELF_FAILURE;
  }
  return ELF_SUCCESS;
}

// Parses a given section header and returns a pointer to the sections contents.
// Returns NULL on failure.
ELF_ERROR elf_get_section_contents(ELF_OBJ *obj, Elf_Shdr *section,
                                   uint8_t **contents) {
  *contents = obj->data + section->sh_offset;
  if (elf_ptr_invalid(obj, *contents)) {
    log_print(LL_ERR, "Can't get section at offset %08x", section->sh_offset);
    return ELF_FAILURE;
  }
  return ELF_SUCCESS;
}
