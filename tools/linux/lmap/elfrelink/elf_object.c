#define _GNU_SOURCE

#include <elf.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include "../log/log.h"
#include "elf_object.h"
#include "elf_relocations.h"
#include "elf_sections.c"
#include "elf_symbols.h"

static const int MODULE_NAME_LEN = 64 - sizeof(unsigned long);
static const char *THIS_MODULE_SECTION = ".gnu.linkonce.this_module";

// Checks if a pointer is actually inside an elf object
ELF_ERROR elf_ptr_invalid(ELF_OBJ *obj, uint8_t *ptr) {
  if (ptr < obj->data || ptr >= obj->data + obj->size) {
    log_print(LL_DBG, "Invalid file offset: %d", ptr - obj->data);
    return ELF_FAILURE;
  }
  return ELF_SUCCESS;
}

// Checks if a string ends in a specific suffix.
ELF_ERROR string_has_suffix(const char *string, const char *suffix) {
  size_t string_len = strlen(string);
  size_t suffix_len = strlen(suffix);
  size_t string_suffix = string_len - suffix_len;

  if (string_len >= suffix_len) {
    if (!strncmp(string + string_suffix, suffix, suffix_len)) {
      return ELF_SUCCESS;
    }
  }
  return ELF_FAILURE;
}

// Finds out if the next section in the file is actually the section header
// table. Returns ELF_SUCCESS if this is true, ELF_ERROR otherwise.
ELF_ERROR elf_shdrtab_is_next(ELF_OBJ *obj, Elf_Word offset) {
  Elf_Shdr *section_after;
  Elf_Word section_after_idx;
  Elf_Ehdr *ehdr;

  if (obj->get_ehdr(obj, &ehdr) != ELF_SUCCESS) {
    log_print(LL_ERR, "Can't get ehdr, aborting search for shdrtab");
    return ELF_FAILURE;
  }
  if (ehdr->e_shoff > offset) {
    // shdrtab is somewhere behind this section
    if (obj->section_after_offset(obj, offset, &section_after,
          &section_after_idx) == ELF_SUCCESS) {
      if (section_after->sh_offset > ehdr->e_shoff) {
        // shdrtab is in front of the next real section
        return ELF_SUCCESS;
      }
    } else {
      // There might be no other section after this one but the shdrtab is
      return ELF_SUCCESS;
    }
  }
  return ELF_FAILURE;
}

// Moves the section header table back in the file.
ELF_ERROR elf_move_shtab_back(ELF_OBJ *obj, Elf_Off offset) {
  Elf_Shdr *section_after;
  Elf_Word section_after_idx;
  Elf_Word shdrtab_size;
  uint8_t *shdrtab;
  Elf_Ehdr *ehdr;

  if (obj->get_ehdr(obj, &ehdr) != ELF_SUCCESS) {
    log_print(LL_ERR, "Can't get ehdr, unable to move shtab");
    return ELF_FAILURE;
  }
  shdrtab_size = ehdr->e_shnum * ehdr->e_shentsize;
  // The section header table might not be at the end of the file
  if (obj->section_after_offset(obj, ehdr->e_shoff, &section_after,
                            &section_after_idx) == ELF_SUCCESS) {
    if (obj->section_move_back(obj, section_after_idx, offset) != ELF_SUCCESS) {
      log_print(LL_ERR, "Unable to move section header table back %d bytes, "
                "there is a section behind it that we can't move",
                offset);
      return ELF_FAILURE;
    }
  }
  shdrtab = obj->data + ehdr->e_shoff;
  if (elf_ptr_invalid(obj, shdrtab)) {
    log_print(LL_ERR, "Can't find shdrtab, invalid file offset %d",
              ehdr->e_shoff);
    return ELF_FAILURE;
  }
  memmove(shdrtab + offset, shdrtab, shdrtab_size);
  ehdr->e_shoff += offset;
  // Refresh the cached pointers
  if (elf_parse_headers(obj) != ELF_SUCCESS) {
    log_print(LL_ERR, "Something went wrong moving the shdrs");
    return ELF_FAILURE;
  }
  return ELF_SUCCESS;
}

// Increases the size of an elf object by growing it at the end.
ELF_ERROR elf_enlarge_obj(ELF_OBJ *obj, Elf_Word amount) {
  if ((obj->size + amount) > obj->bufsize) {
    log_print(LL_ERR, "Cannot grow object from %d to %d bytes, max size is %d",
              obj->size, obj->size + amount, obj->bufsize);
    return ELF_FAILURE;
  }
  obj->size = obj->size + amount;
  return ELF_SUCCESS;
}

// Increases the size of a section. Also pushes all other sections and the
// section header table back, if they are next to it. Will also enlarge the
// object so no need to call that before.
ELF_ERROR elf_enlarge_section(ELF_OBJ *obj, Elf_Word section_idx,
    Elf_Word amount) {
  Elf_Shdr *section = NULL, *tmp_section = NULL;
  Elf_Word tmp_section_idx;

  if (obj->section_by_idx(obj, section_idx, &section) != ELF_SUCCESS) {
    log_print(LL_ERR, "Failed to get section %d to enlarge", section_idx);
    return ELF_FAILURE;
  }
  if (elf_enlarge_obj(obj, amount) != ELF_SUCCESS) {
    log_print(LL_ERR, "Couldn't enlarge elf object to fit larger section");
    return ELF_FAILURE;
  }
  if (elf_shdrtab_is_next(obj, section->sh_offset) == ELF_SUCCESS) {
    if (elf_move_shtab_back(obj, amount)) {
      log_print(LL_ERR, "Failed to push shtab back");
      return ELF_FAILURE;
    }
    // Any sction pointers need to be fixed because the shdr just moved
    section = (Elf_Shdr *) (((uint8_t *) section) + amount);
  } else {
    if (obj->section_after_offset(obj, section->sh_offset, &tmp_section,
          &tmp_section_idx) == ELF_SUCCESS) {
      if (obj->section_move_back(obj, tmp_section_idx, amount) != ELF_SUCCESS) {
        log_print(LL_ERR, "Failed to push back section");
        return ELF_FAILURE;
      }
    }
  }
  // Get a new pointer to section as the shdrs might have moved
  if (obj->section_by_idx(obj, section_idx, &section) != ELF_SUCCESS) {
    log_print(LL_ERR, "Failed to get section %d to enlarge", section_idx);
    return ELF_FAILURE;
  }
  section->sh_size += amount;
  log_print(LL_DBG, "Sucessfully enlarged section %d by %d bytes", section_idx,
      amount);
  return ELF_SUCCESS;
}

// Increases the size of the symbol table and adds a new entry.
//
// Args:
//  obj: Pointer to an elf object
//  sym: Pointer to the symbol to insert into the symtab
//  idx: Pointer to an Elf_Word to write the new symbols index to.
//
// Returns: ELF_SUCCESS or ELF_ERROR on failure.
//
ELF_ERROR elf_add_symtab_entry(ELF_OBJ *obj, Elf_Sym *sym, Elf_Word *idx) {
  uint8_t *new_sym;
  Elf_Shdr *symtab;
  Elf_Off sym_off;
  Elf_Word symtab_idx;
  Elf_Xword num_syms;

  if (obj->section_by_name(obj, ".symtab", &symtab_idx, &symtab)
      != ELF_SUCCESS) {
    log_print(LL_ERR, "Can't add symtab entry, .symtab not found");
    return ELF_FAILURE;
  }
  sym_off = symtab->sh_offset + symtab->sh_size;
  num_syms = symtab->sh_size / symtab->sh_entsize;

  *idx = num_syms;  // Put new entry at the end
  log_print(LL_DBG, "Enlarging .symtab to fit new entry");
  if (elf_enlarge_section(obj, symtab_idx, sizeof(Elf_Sym))
      != ELF_SUCCESS) {
    log_print(LL_ERR, "Failed to enlarge symtab by %d, can't add symbol",
              sizeof(Elf_Sym));
    return ELF_FAILURE;
  }
  new_sym = obj->data + sym_off;
  if (elf_ptr_invalid(obj, new_sym)) {
    log_print(LL_ERR, "Failed to get pointer to symbol, offset %08x invalid",
              sym_off);
    return ELF_FAILURE;
  }
  memcpy(new_sym, (uint8_t *) sym, sizeof(Elf_Sym));
  if (elf_parse_headers(obj)) {
    log_print(LL_ERR, "Elf header corrupted");
    return ELF_FAILURE;
  }

  return ELF_SUCCESS;
}

// Adds a new string to a given string table. Stores the offset where it placed
// the new string in 'offset'.
//
// Args:
//  obj: this pointer
//  strtab_idx: index of the string table in the shdr table
//  entry: string to add to table
//  offset: pointer to caller int to store new offset of string in stringtab
//
ELF_ERROR elf_add_strtab_entry(ELF_OBJ *obj, Elf_Word strtab_idx, char *entry,
    Elf_Word *offset) {
  uint8_t *new_entry;
  Elf_Shdr *strtab = NULL;
  Elf_Word entry_off;
  size_t entry_len = strlen(entry) + 1;
  // shdrstrtab_entry_off = obj->shstrtab->sh_size;
  // shdrstrtab_off = obj->shstrtab->sh_offset + shdrstrtab_entry_off;
  if (obj->section_by_idx(obj, strtab_idx, &strtab)) {
    log_print(LL_ERR, "Failed to add strtab entry %s to strtab %d, "
        "no stringtable found at this index", entry, strtab_idx);
    return ELF_FAILURE;
  }
  entry_off = strtab->sh_size;
  log_print(LL_DBG, "Enlarging strtab by %d to fit %s", entry_len, entry);
  if (elf_enlarge_section(obj, strtab_idx, entry_len)) {
    log_print(LL_ERR, "Failed to enlarge strtab to insert %s", entry);
    return ELF_FAILURE;
  }
  if (obj->section_by_idx(obj, strtab_idx, &strtab) != ELF_SUCCESS) {
    log_print(LL_ERR, "Failed to add strtab entry %s to strtab %d, "
        "no stringtable found at this index", entry, strtab_idx);
    return ELF_FAILURE;
  }
  *offset = entry_off;  // put new entry at the end
  log_print(LL_DBG, "adding strtab entry to strtab at %d of size %d",
            strtab->sh_offset, strtab->sh_size);
  new_entry = obj->data + strtab->sh_offset + entry_off;
  if (elf_ptr_invalid(obj, new_entry)) {
    log_print(LL_ERR, "Failed to insert entry %s into strtab, "
              "offset out of file",
              entry);
    return ELF_FAILURE;
  }
  memcpy(new_entry, entry, entry_len);
  return ELF_SUCCESS;
}

// Add a new section header to the section header table.
// Resizes the table and moves subsequent sections back.
//
// Args:
//  obj: this pointer
//  shdr: pointer to the shdr to add
//  name: name of the shdr, to add to shstrtab
//  section_off: offset of the sectoin in the object (allows easy copying of
//    shdr, as you can just specify a new offset and the function will adapt).
//  shdr_idx: Pointer to caller int where the index in the shdr table of the
//    new shdr will be stored.
//
ELF_ERROR elf_add_shdr(ELF_OBJ *obj, Elf_Shdr *shdr, Elf_Word name,
    Elf_Word section_off, Elf_Word *shdr_idx) {
  Elf_Shdr *shdr_table = NULL, *tmp_section, *new_shdr;
  Elf_Word tmp_section_idx;
  Elf_Ehdr *ehdr;

  if (obj->get_ehdr(obj, &ehdr) != ELF_SUCCESS) {
    log_print(LL_ERR, "Can't add shdr entry, ehdr not found");
    return ELF_FAILURE;
  }
  if (elf_enlarge_obj(obj, sizeof(Elf_Shdr)) != ELF_SUCCESS) {
    log_print(LL_ERR, "Couldn't enlarge elf object to fit larger section");
    return ELF_FAILURE;
  }
  // We will add a new shdr entry, so move anything thats at the end of the shdr
  // table back a bit to make room for it.
  if (obj->section_after_offset(obj, ehdr->e_shoff, &tmp_section,
        &tmp_section_idx) == ELF_SUCCESS) {
    log_print(LL_DBG, "Moving sections next to shdrtab back %d bytes to make "
              "space for new shdr entry", sizeof(Elf_Shdr));
    if (obj->section_move_back(obj, tmp_section_idx, sizeof(Elf_Shdr))
        != ELF_SUCCESS) {
      log_print(LL_ERR, "Failed to move section after shdrtab");
      return ELF_FAILURE;
    }
  }
  log_print(LL_DBG, "Adding shdrtab entry for new section");
  if (obj->get_shdr(obj, &shdr_table) != ELF_SUCCESS) {
    log_print(LL_ERR, "Can't add shdr entry, shdr table not found");
    return ELF_FAILURE;
  }
  new_shdr = (shdr_table + ehdr->e_shnum);
  if (elf_ptr_invalid(obj, (uint8_t *) new_shdr)) {
    log_print(LL_ERR, "Failed to add new shdrtab entry, offset out of file");
    return ELF_FAILURE;
  }
  // Copy the section header over
  memcpy(new_shdr, shdr, sizeof(Elf_Shdr));
  // Return the number of the new entry
  *shdr_idx = ehdr->e_shnum;
  // Fixup references
  ehdr->e_shnum++;
  new_shdr->sh_offset = section_off;
  new_shdr->sh_name = name;
  if (elf_parse_headers(obj)) {
    log_print(LL_ERR, "Elf header corrupted");
    return ELF_FAILURE;
  }

  return ELF_SUCCESS;
}

// Removes any dependencies a module might have by overwriting the 'depends='
// string in .modinfo with zeroes.
ELF_ERROR elf_clean_dependencies(ELF_OBJ *obj) {
  Elf_Shdr *modinfo;
  uint8_t *modinfo_content;
  char *dependencies;
  size_t dependencies_len;
  const char *dep_prefix = "depends=";
  size_t dep_prefix_len = strlen(dep_prefix);
  Elf_Word modinfo_idx;

  if (obj->section_by_name(obj, ".modinfo", &modinfo_idx, &modinfo)
      != ELF_SUCCESS) {
    log_print(LL_ERR, "No need to clean dependencies, .modinfo does not exist");
    return ELF_SUCCESS;
  }
  if (obj->section_get_contents(obj, modinfo, &modinfo_content)
      != ELF_SUCCESS) {
    log_print(LL_ERR, "Failed to get .modinfo contents, still it exists");
    return ELF_FAILURE;
  }
  if ((dependencies = (char *)memmem(modinfo_content, modinfo->sh_size,
          dep_prefix, dep_prefix_len)) == NULL) {
    log_print(LL_LOG, "Module has no dependencies, no need to clean up");
    return ELF_SUCCESS;
  }
  dependencies_len = strlen(dependencies);
  log_print(LL_DBG, "Cleaning dependency string %s of len %d", dependencies,
            dependencies_len);
  memset(dependencies, 0x00, dependencies_len);
  return ELF_SUCCESS;
}

// Change the module name by overwriting it in section .gnu.linkone.this_module
ELF_ERROR elf_rename_module(ELF_OBJ *obj, char *old_name, char *new_name) {
  uint8_t *this_module = NULL;
  char *module_name = NULL;
  Elf_Word this_module_idx = 0;
  Elf_Shdr *this_module_shdr = NULL;

  if (strlen(new_name) >= MODULE_NAME_LEN) {
    log_print(LL_ERR, "Can't rename module %s to %s, "
        "new name too long (limit: %d)", old_name, new_name, MODULE_NAME_LEN);
    return ELF_FAILURE;
  }
  if (obj->section_by_name(obj, THIS_MODULE_SECTION,
        &this_module_idx, &this_module_shdr) != ELF_SUCCESS) {
    log_print(LL_ERR, "Can't rename module, section %s not found",
        THIS_MODULE_SECTION);
    return ELF_FAILURE;
  }
  if (obj->section_get_contents(obj, this_module_shdr, &this_module)
      != ELF_SUCCESS) {
    log_print(LL_ERR, "Can't rename module, section %s contents not found",
        THIS_MODULE_SECTION);
    return ELF_FAILURE;
  }
  module_name = memmem(this_module, this_module_shdr->sh_size, old_name,
      strlen(old_name));
  if (module_name == NULL) {
    log_print(LL_ERR, "Can't rename module, name (%s) not found in %s",
        old_name, THIS_MODULE_SECTION);
    return ELF_FAILURE;
  }
  // this_module.name has enough space to fit any module name, because:
  // char name[MODULE_NAME_LEN];
  // #define MODULE_NAME_LEN (64 - sizeof(unsigned long))
  strncpy(module_name, new_name, MODULE_NAME_LEN);
  return ELF_SUCCESS;
}

// Verifies that a valid elf header for a ET_REL file is present and the flags
// for machine type and architecture match this binary.
ELF_ERROR elf_verify_ehdr(Elf_Ehdr *ehdr) {
  if (strncmp((char *) ehdr->e_ident, ELFMAG, 4)) {
    log_print(LL_ERR, "Input is not a valid ELF file");
    return ELF_FAILURE;
  }
  if (ehdr->e_type != ET_REL) {
    log_print(LL_ERR, "Input is not a relocatable object");
    return ELF_FAILURE;
  }
  // TODO: Adapt this when we support 32 bit and/or ARM
  if (ehdr->e_machine != ELF_MACHINE) {
    log_print(LL_ERR, "Input file is build for wrong architecture");
    return ELF_FAILURE;
  }
  return ELF_SUCCESS;
}

// Get a pointer to the ehdr in memory
//
// Args:
//  obj: this pointer to the ELF_OBJ
//  ehdr: pointer to the ehdr pointer to set
//
// Returns: ELF_SUCCESS or ELF_FAILURE
//
ELF_ERROR elf_get_ehdr(ELF_OBJ *obj, Elf_Ehdr **ehdr) {
  if (obj->data == NULL) {
    log_print(LL_ERR, "ELF object not in memory, can't find ehdr");
    return ELF_FAILURE;
  }
  // The ELF headers are at the beginning of the file
  *ehdr = (Elf_Ehdr *) obj->data;
  return ELF_SUCCESS;
}

// Get a pointer to the section header table in memory
//
// Args:
//  obj: this pointer to the ELF_OBJ
//  shdr: pointer to the shdr pointer to set
//
// Returns: ELF_SUCCESS or ELF_FAILURE
//
ELF_ERROR elf_get_shdr(ELF_OBJ *obj, Elf_Shdr **shdr) {
  Elf_Ehdr *ehdr;
  if (obj->get_ehdr(obj, &ehdr) != ELF_SUCCESS) {
    log_print(LL_ERR, "Can't get section headers, ehdr not found");
    return ELF_FAILURE;
  }
  *shdr = (Elf_Shdr *) (obj->data + ehdr->e_shoff);
  if (elf_ptr_invalid(obj, (uint8_t *) *shdr)) {
    log_print(LL_ERR, "Can't locate section header table, offset not in "
        "file: %d", ehdr->e_shoff);
    return ELF_FAILURE;
  }
  return ELF_SUCCESS;
}

ELF_ERROR elf_get_shstrtab(struct ELF_OBJ_T *obj, Elf_Shdr **shstrtab,
    Elf_Word *shstrtab_idx) {
  Elf_Ehdr *ehdr = NULL;

  if (obj->get_ehdr(obj, &ehdr) != ELF_SUCCESS) {
    log_print(LL_ERR, "Can't get shstrtab, ehdr not found");
    return ELF_FAILURE;
  }
  if (obj->section_by_idx(obj, ehdr->e_shstrndx, shstrtab) != ELF_SUCCESS) {
    log_print(LL_ERR, "Can't get shstrtab, shdr idx is %d but this section "
        "does not exist", ehdr->e_shstrndx);
    return ELF_FAILURE;
  }
  *shstrtab_idx = ehdr->e_shstrndx;
  return ELF_SUCCESS;
}

// Parse the headers in an elf object and make sure it's a valid ELF
ELF_ERROR elf_parse_headers(ELF_OBJ *obj) {
  Elf_Ehdr *ehdr;
  Elf_Shdr *shdr;

  if (obj->get_ehdr(obj, &ehdr) != ELF_SUCCESS) {
    log_print(LL_ERR, "Can't locate ELF Header");
    return ELF_FAILURE;
  }
  if (obj->get_shdr(obj, &shdr) != ELF_SUCCESS) {
    log_print(LL_ERR, "Can't locate Section Header");
    return ELF_FAILURE;
  }
  return ELF_SUCCESS;
}

// Fill in the vtable for symbol related functions.
void elf_symbols_vtable(ELF_OBJ *obj) {
  obj->symbol_get_name = elf_get_symbol_name;
  obj->symbol_by_idx = elf_get_symbol;
  obj->symbol_by_name = elf_get_symbol_by_name;
  obj->symbol_by_suffix = elf_get_symbol_by_suffix;
  obj->symbol_to_section = elf_get_symbol_to_section;
  obj->symbol_exist = elf_contains_syms;
  obj->symbol_exist_suffix = elf_contains_syms_with_suffix;
  obj->symbol_exist_named_suffix = elf_contains_syms_with_named_suffix;
}

// Fill in the vtable for section related functions.
void elf_sections_vtable(ELF_OBJ *obj) {
  obj->section_by_idx = elf_get_section;
  obj->section_by_name = elf_get_section_by_name;
  obj->section_by_suffix = elf_get_section_by_suffix;
  obj->section_after_offset = elf_get_section_after;
  obj->section_get_name = elf_get_section_name;
  obj->section_get_contents = elf_get_section_contents;
  obj->section_move_back = elf_move_section_back;
}

// Fill in the vtable for relocation related functions.
void elf_relocations_vtable(ELF_OBJ *obj) {
  obj->relocation_to_section = elf_rela_section;
  obj->relocation_by_symbol = elf_find_all_rela_in_sec;
  obj->relocation_exist_to_sym = elf_has_rela_to_sym;
}

// Sets up the vtables to the correct functions
//
// Args:
//  obj: pointer to the elf object to init
//
void elf_init_vtables(ELF_OBJ *obj) {
  obj->get_ehdr = elf_get_ehdr;
  obj->get_shdr = elf_get_shdr;
  obj->get_shstrtab = elf_get_shstrtab;
  elf_sections_vtable(obj);
  elf_symbols_vtable(obj);
  elf_relocations_vtable(obj);
}

// Creates a new elf object from a file already in memory.
//
// Args:
//  data: pointer to the file in memory
//  len: size of the file in memory
//  obj: pointer to an obj to initialize
//  excess: How much to overallocate (to easily add data to the elf).
//
// Returns: ELF_SUCCESS on success, or ELF_ERROR on failure
//
ELF_ERROR elf_from_mem(uint8_t *data, size_t len, ELF_OBJ *obj,
                                size_t excess) {
  bzero(obj, sizeof(ELF_OBJ));
  elf_init_vtables(obj);
  // Create our own copy of the object to make sure we can modify it.
  obj->data = (uint8_t *) malloc(len + excess);
  memcpy(obj->data, data, len);
  obj->size = len;
  obj->bufsize = len + excess;
  if (elf_verify_ehdr((Elf_Ehdr *) data) != ELF_SUCCESS) {
    log_print(LL_ERR, "Elf header corrupted");
    return ELF_FAILURE;
  }
  if (elf_parse_headers(obj) != ELF_SUCCESS) {
    log_print(LL_ERR, "Failed to create elf object, memory buffer does not "
              "contain valid elf relocatable object file");
    return ELF_FAILURE;
  }
  return ELF_SUCCESS;
}

// Opens an elf relocatable object, loads it into memory, parses the headers
// and performs sanity checking. Caller must free the allocated buffer
// using elf_free_obj().
//
// Args:
//  path: Path to the object file.
//  obj: Struct that will be populated.
//  excess: How much to overallocate (to easily add data to the elf).
//
// Returns: ELF_SUCCESS or ELF_ERROR.
//
ELF_ERROR elf_from_file(const char *path, ELF_OBJ *obj, size_t excess) {
  FILE *fp;
  struct stat st;

  elf_init_vtables(obj);
  if (stat(path, &st) < 0) {
    perror("[-] Can't open input file: ");
    goto error_stat;
  }
  obj->size = st.st_size;
  obj->bufsize = obj->size + excess;
  if (!(fp = fopen(path, "r"))) {
    perror("[-] Can't open input file: ");
    goto error_stat;
  }
  if ((obj->data = (uint8_t *) malloc(obj->size + excess)) == NULL) {
    perror("[-] Can't allocate memory for input file: ");
    goto error_malloc;
  }
  if (!fread(obj->data, obj->size, 1, fp)) {
    perror("[-] Can't read input file: ");
    goto error;
  }
  if (elf_verify_ehdr((Elf_Ehdr *) obj->data) != ELF_SUCCESS) {
    log_print(LL_ERR, "Elf header corrupted");
    return ELF_FAILURE;
  }
  if (elf_parse_headers(obj)) {
    log_print(LL_ERR, "Elf headers incomplete or damaged, can't parse file");
    goto error;
  }
  fclose(fp);
  return ELF_SUCCESS;

  error: free(obj->data);
  error_malloc: fclose(fp);
  error_stat: return ELF_FAILURE;
}

// Writes an object out to the filesystem
ELF_ERROR elf_to_file(const char *path, ELF_OBJ *obj) {
  FILE *fp;
  ELF_ERROR status = ELF_FAILURE;

  if (!(fp = fopen(path, "w+"))) {
    perror("Can't open ouput file: ");
    goto error_fopen;
  }
  if (!fwrite((void *) obj->data, obj->size, 1, fp)) {
    perror("Can't write to output file: ");
    goto error;
  }
  status = ELF_SUCCESS;
  error: fclose(fp);
  error_fopen: return status;
}

// Frees any memory the object's members occupy
ELF_ERROR elf_free_obj(ELF_OBJ *obj) {
  free(obj->data);
  return ELF_SUCCESS;
}
