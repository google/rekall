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
#include <strings.h>

#include "utest.h"

#include "../elfrelink/elf_generic.h"
#include "../elfrelink/elf_object.h"
#include "../elfrelink/elfrelink.h"
#include "../log/log.h"

// This is known good testdata in encoded arrays
#include "test_data/parasite.shstrtab.h"
#include "test_data/host.strtab.h"

// These paths are relative from the directory of the makefile.
static const char *test_parasite_path= "test_data/parasite";
static const char *test_host_path= "test_data/host";
static const char *out_path = "test_module.ko";

// This object is initialized for testing reads only
ELF_OBJ parasite_obj;
// This one will be allowed to be changed
ELF_OBJ host_obj;
// The write obj will be overallocated by 10MB to enable adding of things
const size_t obj_excess = 10 * 1024 * 1024;

void init_tests(void) {
  // Restrict the logging to error messages to avoid cluttering test output.
  loglevel = LL_LOG;
  assert(elf_from_file(test_parasite_path, &parasite_obj, obj_excess)
         == ELF_SUCCESS);
  assert(elf_from_file(test_host_path, &host_obj, obj_excess) == ELF_SUCCESS);
}

void cleanup_tests(void) {
  assert(elf_free_obj(&parasite_obj) == ELF_SUCCESS);
  assert(elf_free_obj(&host_obj) == ELF_SUCCESS);
}

void reset_tests(void) {
  cleanup_tests();
  init_tests();
}

void test_read_obj(void) {
  ELF_OBJ obj;
  Elf_Ehdr *ehdr;
  Elf_Shdr *shstrtab, *symtab, *strtab;
  Elf_Word shstrtab_idx, symtab_idx, strtab_idx;

  assert(elf_from_file(test_host_path, &obj, 0) == ELF_SUCCESS);
  assert(obj.get_ehdr(&obj, &ehdr) == ELF_SUCCESS);
  assert(ehdr->e_shstrndx == 24);
  assert(ehdr->e_shoff == 20344);
  assert(obj.section_by_name(&obj, ".shstrtab", &shstrtab_idx, &shstrtab)
      == ELF_SUCCESS);
  assert(shstrtab_idx == 24);
  assert(obj.section_by_name(&obj, ".strtab", &strtab_idx, &strtab)
      == ELF_SUCCESS);
  assert(strtab_idx == 22);
  assert(obj.section_by_name(&obj, ".symtab", &symtab_idx, &symtab)
      == ELF_SUCCESS);
  assert(symtab_idx == 21);
}

void test_read_obj_from_mem(void) {
  FILE *fp = NULL;
  struct stat st;
  uint8_t *buf = 0;
  ELF_OBJ obj;
  Elf_Ehdr *ehdr;

  assert(stat(test_host_path, &st) == 0);
  assert((fp = fopen(test_host_path, "r")) != NULL);
  assert((buf = malloc(st.st_size)) != NULL);
  assert((fread(buf, st.st_size, 1, fp)) == 1);
  assert(elf_from_mem(buf, st.st_size, &obj, 0) == ELF_SUCCESS);
  assert(obj.get_ehdr(&obj, &ehdr) == ELF_SUCCESS);
  assert(ehdr->e_shstrndx == 24);
  assert(ehdr->e_shoff == 20344);
}

void test_pointer_invalid(void) {
  Elf_Ehdr *parasite_ehdr;
  Elf_Shdr *parasite_shdr, *parasite_strtab, *parasite_symtab, *parasite_shstrtab;
  Elf_Word parasite_strtab_idx, parasite_symtab_idx, parasite_shstrtab_idx;

  assert(elf_ptr_invalid(&parasite_obj, NULL) == ELF_FAILURE);
  assert(elf_ptr_invalid(&parasite_obj, parasite_obj.data + parasite_obj.size)
         == ELF_FAILURE);
  assert(parasite_obj.get_ehdr(&parasite_obj, &parasite_ehdr) == ELF_SUCCESS);
  assert(elf_ptr_invalid(&parasite_obj, (uint8_t *)parasite_ehdr)
         == ELF_SUCCESS);
  assert(parasite_obj.get_shdr(&parasite_obj, &parasite_shdr) == ELF_SUCCESS);
  assert(elf_ptr_invalid(&parasite_obj, (uint8_t *)parasite_shdr)
         == ELF_SUCCESS);
  assert(parasite_obj.section_by_name(&parasite_obj, ".strtab",
        &parasite_strtab_idx, &parasite_strtab) == ELF_SUCCESS);
  assert(elf_ptr_invalid(&parasite_obj, (uint8_t *)parasite_strtab)
         == ELF_SUCCESS);
  assert(parasite_obj.section_by_name(&parasite_obj, ".symtab",
        &parasite_symtab_idx, &parasite_symtab) == ELF_SUCCESS);
  assert(elf_ptr_invalid(&parasite_obj, (uint8_t *)parasite_symtab)
         == ELF_SUCCESS);
  assert(parasite_obj.section_by_name(&parasite_obj, ".shstrtab",
        &parasite_shstrtab_idx, &parasite_shstrtab) == ELF_SUCCESS);
  assert(elf_ptr_invalid(&parasite_obj, (uint8_t *)parasite_shstrtab)
         == ELF_SUCCESS);
}

void test_parse_headers(void) {
  Elf_Ehdr *ehdr;
  Elf_Shdr *shdr;
  Elf_Shdr *shstrtab, *strtab, *symtab;
  Elf_Word shstrtab_idx, strtab_idx, symtab_idx;

  assert(elf_parse_headers(&parasite_obj) == ELF_SUCCESS);
  parasite_obj.get_ehdr(&parasite_obj, &ehdr);
  assert(ehdr == (Elf_Ehdr *)parasite_obj.data);
  parasite_obj.get_shdr(&parasite_obj, &shdr);
  assert(shdr == (Elf_Shdr *)(parasite_obj.data + 9896));
  parasite_obj.section_by_name(&parasite_obj, ".shstrtab", &shstrtab_idx,
      &shstrtab);
  assert(shstrtab_idx == 17);
  assert(shstrtab->sh_offset == 0x25ec);
  parasite_obj.section_by_name(&parasite_obj, ".strtab", &strtab_idx, &strtab);
  assert(strtab_idx == 19);
  assert(strtab->sh_offset == 0x4168);
  parasite_obj.section_by_name(&parasite_obj, ".symtab", &symtab_idx, &symtab);
  assert(symtab_idx == 18);
  assert(symtab->sh_offset == 0x3a48);
}

void test_get_symbol(void) {
  Elf_Sym *sym;
  Elf_Word idx;
  char *name;

  assert(parasite_obj.symbol_by_idx(&parasite_obj, 55, &sym) == ELF_SUCCESS);
  assert(sym->st_shndx == 14);
  assert(sym->st_value == 0);
  assert(sym->st_size == 8);
  assert(parasite_obj.symbol_get_name(&parasite_obj, sym->st_name, &name)
         == ELF_SUCCESS);
  assert(strcmp(name, "pte_mmap") == 0);
  assert(parasite_obj.symbol_by_name(&parasite_obj, "pte_mmap", &sym, &idx)
         == ELF_SUCCESS);
  assert(idx == 55);
  assert(sym->st_shndx == 14);
  assert(sym->st_value == 0);
  assert(sym->st_size == 8);
  assert(parasite_obj.symbol_by_idx(&parasite_obj, 56, &sym) == ELF_SUCCESS);
  assert(sym->st_shndx == 2);
  assert(sym->st_value == 0x85);
  assert(sym->st_size == 103);
  assert(parasite_obj.symbol_get_name(&parasite_obj, sym->st_name, &name)
         == ELF_SUCCESS);
  assert(strcmp(name, "pmem_llseek") == 0);
}

void test_get_symbol_name(void) {
  Elf_Sym *sym;
  char *name;

  assert(parasite_obj.symbol_by_idx(&parasite_obj, 17, &sym) == ELF_SUCCESS);
  assert(sym->st_shndx == 8);
  assert(sym->st_value == 0x10);
  assert(sym->st_size == 8);
  assert(parasite_obj.symbol_get_name(&parasite_obj, sym->st_name, &name)
         == ELF_SUCCESS);
  assert(strcmp("vvaraddr_vsyscall_gtod_data", name) == 0);
}

void test_get_section(void) {
  Elf_Ehdr *parasite_ehdr;
  Elf_Shdr *shdr;
  char *name;
  uint8_t *buf;
  Elf_Word idx;

  assert(parasite_obj.get_ehdr(&parasite_obj, &parasite_ehdr) == ELF_SUCCESS);
  assert(parasite_obj.section_by_idx(&parasite_obj, 17, &shdr) == ELF_SUCCESS);
  assert(shdr->sh_offset == 0x25ec);
  assert(shdr->sh_size == 0xb8);
  assert(parasite_obj.section_get_name(&parasite_obj, shdr, &name)
      == ELF_SUCCESS);
  assert(strcmp(name, ".shstrtab") == 0);
  assert(parasite_obj.section_by_name(&parasite_obj, ".shstrtab", &idx, &shdr)
         == ELF_SUCCESS);
  assert(parasite_obj.section_get_contents(&parasite_obj, shdr, &buf)
      == ELF_SUCCESS);
  assert(buf == parasite_obj.data + shdr->sh_offset);
  assert(memcmp(__parasite_shstrtab, buf, __parasite_shstrtab_len) == 0);
  assert(parasite_obj.section_after_offset(&parasite_obj,
        parasite_ehdr->e_shoff, &shdr, &idx) == ELF_SUCCESS);
  assert(idx == 3);
  assert(parasite_obj.section_get_name(&parasite_obj, shdr, &name)
      == ELF_SUCCESS);
  assert(strcmp(name, ".rela.text") == 0);
  assert(parasite_obj.section_after_offset(&parasite_obj, shdr->sh_offset,
        &shdr, &idx) == ELF_SUCCESS);
  assert(idx == 5);
  assert(parasite_obj.section_get_name(&parasite_obj, shdr, &name)
      == ELF_SUCCESS);
  assert(strcmp(name, ".rela.init.text") == 0);
}

void test_get_section_after(void) {
  Elf_Shdr *shdr, *shdr_after;
  Elf_Word idx, idx_after;

  assert(parasite_obj.section_by_name(&parasite_obj, ".text", &idx, &shdr)
         == ELF_SUCCESS);
  assert(shdr->sh_offset == 0x64);
  assert(shdr->sh_size = 0x1748);
  assert(idx == 2);

  assert(parasite_obj.section_after_offset(&parasite_obj, shdr->sh_offset,
        &shdr_after, &idx_after) == ELF_SUCCESS);
  assert(idx_after == 4);
  assert(shdr_after->sh_offset == 0x17ac);
  assert(shdr_after->sh_size == 0x94);

  assert(host_obj.section_by_name(&host_obj, ".rela.gnu.linkonce.this_module",
        &idx, &shdr) == ELF_SUCCESS);
  assert(shdr->sh_offset == 0x3db0);
  assert(shdr->sh_size = 0x30);
  assert(idx == 19);

  assert(host_obj.section_after_offset(&host_obj, shdr->sh_offset, &shdr_after,
        &idx_after) == ELF_SUCCESS);
  assert(idx_after == 21);
  assert(shdr_after->sh_offset == 0x3de0);
  assert(shdr_after->sh_size == 0xae0);

  assert(parasite_obj.section_by_name(&parasite_obj, ".strtab", &idx, &shdr)
        == ELF_SUCCESS);
  assert(shdr->sh_offset == 0x4168);
  assert(shdr->sh_size = 0x357);
  assert(idx == 19);

  assert(parasite_obj.section_after_offset(&parasite_obj, shdr->sh_offset,
        &shdr_after, &idx_after) == ELF_FAILURE);
}

void test_enlarge_section(void) {
  Elf_Shdr *shdr, *shdr_after;
  Elf_Word idx, idx_after;
  size_t obj_size, section_size, enlargement = 1337;

  assert(host_obj.section_by_name(&host_obj, ".strtab", &idx, &shdr)
      == ELF_SUCCESS);
  assert(idx == 22);
  assert(shdr->sh_offset == 0x48c0);
  assert(shdr->sh_size == 0x5c8);
  assert(host_obj.size == 21944);
  assert(host_obj.section_after_offset(&host_obj, shdr->sh_offset, &shdr_after,
        &idx_after) == ELF_SUCCESS);
  assert(idx_after == 23);
  assert(shdr_after->sh_offset == 0x4e88);
  obj_size = host_obj.size;
  section_size = shdr->sh_size;
  assert(elf_enlarge_section(&host_obj, idx, enlargement) == ELF_SUCCESS);
  assert(host_obj.section_by_name(&host_obj, ".strtab", &idx, &shdr)
         == ELF_SUCCESS);
  assert(shdr->sh_size == section_size + enlargement);
  assert(host_obj.size == obj_size + enlargement);
  assert(host_obj.section_after_offset(&host_obj, shdr->sh_offset, &shdr_after,
        &idx_after) == ELF_SUCCESS);
  assert(idx_after == 23);
  assert(shdr_after->sh_offset == 0x4e88 + enlargement);
}

void test_shdrtab_is_next(void) {
  Elf_Shdr *shdr;
  Elf_Ehdr *ehdr;
  Elf_Word idx;

  assert(parasite_obj.section_by_name(&parasite_obj, ".shstrtab", &idx, &shdr)
         == ELF_SUCCESS);
  assert(shdr->sh_offset == 0x25ec);
  assert(parasite_obj.get_ehdr(&parasite_obj, &ehdr) == ELF_SUCCESS);
  assert(ehdr->e_shoff == 9896);
  assert(elf_shdrtab_is_next(&parasite_obj, shdr->sh_offset) == ELF_SUCCESS);
  assert(parasite_obj.section_by_name(&parasite_obj, ".rela.text", &idx, &shdr)
         == ELF_SUCCESS);
  assert(elf_shdrtab_is_next(&parasite_obj, shdr->sh_offset) == ELF_FAILURE);
  assert(parasite_obj.section_by_name(&parasite_obj, ".text", &idx, &shdr)
         == ELF_SUCCESS);
  assert(elf_shdrtab_is_next(&parasite_obj, shdr->sh_offset) == ELF_FAILURE);
  assert(parasite_obj.section_by_name(&parasite_obj, ".rela.exit.text", &idx,
        &shdr) == ELF_SUCCESS);
  assert(elf_shdrtab_is_next(&parasite_obj, shdr->sh_offset) == ELF_FAILURE);
}

// TODO(jstuettgen): do this with a section in front of the shdr
void test_insert_strtab(void) {
  Elf_Shdr *shdr, *shdr_after;
  Elf_Word idx, idx_after, new_entry_idx;
  char *new_entry = "test_strtab_entry";
  const size_t new_entry_len = strlen(new_entry) + 1;
  size_t obj_size = host_obj.size;
  uint8_t *buf = NULL;
  uint8_t *new_strtab_buf = NULL;

  assert(host_obj.section_by_name(&host_obj, ".strtab", &idx, &shdr)
         == ELF_SUCCESS);
  assert(idx == 22);
  assert(shdr->sh_offset == 0x48c0);
  assert(shdr->sh_size == 0x5c8);
  assert(host_obj.section_get_contents(&host_obj, shdr, &buf) == ELF_SUCCESS);
  assert(memcmp(host_strtab, buf, host_strtab_len) == 0);
  // this was just to get a baseline, now insert stuff and test again
  assert(host_obj.section_after_offset(&host_obj, shdr->sh_offset, &shdr_after,
        &idx_after) == ELF_SUCCESS);
  // make sure this is really the next section
  assert(idx_after == 23);
  assert(shdr_after->sh_offset == 0x4e88);
  assert(elf_add_strtab_entry(&host_obj, idx, new_entry, &new_entry_idx)
         == ELF_SUCCESS);
  assert(host_obj.size == obj_size + new_entry_len);
  assert(host_obj.section_by_name(&host_obj, ".strtab", &idx, &shdr)
         == ELF_SUCCESS);
  assert(idx == 22);
  assert(shdr->sh_offset == 0x48c0);
  assert(shdr->sh_size == 0x5c8 + new_entry_len);
  assert(host_obj.section_after_offset(&host_obj, shdr->sh_offset, &shdr_after,
        &idx_after) == ELF_SUCCESS);
  // make sure the section behind has moved
  assert(shdr_after->sh_offset == 0x4e88 + new_entry_len);
  // Build a known good version of the new strtab in memory
  new_strtab_buf = (uint8_t *)malloc(host_strtab_len + new_entry_len);
  assert(new_strtab_buf != NULL);
  memcpy(new_strtab_buf, buf, host_strtab_len);
  memcpy(new_strtab_buf + host_strtab_len, new_entry, new_entry_len);
  // Now compare to modified strtab in obj
  assert(shdr->sh_size == host_strtab_len + new_entry_len);
  assert(host_obj.section_get_contents(&host_obj, shdr, &buf) == ELF_SUCCESS);
  assert(memcmp(new_strtab_buf, buf, host_strtab_len + new_entry_len) == 0);
  free(new_strtab_buf);
}

void test_add_shdr(void) {
  Elf_Shdr test_shdr;
  Elf_Word idx;

  bzero(&test_shdr, sizeof(test_shdr));
  assert(elf_add_shdr(&host_obj, &test_shdr, 0, 0, &idx) == ELF_SUCCESS);
  assert(idx == 25);
}

void test_move_section(void) {
  Elf_Shdr *shdr, *host_shdr, *shdr_after, *shdr_old;
  Elf_Ehdr *host_ehdr;
  Elf_Word idx, idx_after, shdr_off_old;
  size_t shift = 1337, num_sec_after = 21;
  assert(host_obj.get_ehdr(&host_obj, &host_ehdr) == ELF_SUCCESS);
  Elf_Shdr *shdr_after_old[host_ehdr->e_shnum];

  assert(elf_enlarge_obj(&host_obj, shift) == ELF_SUCCESS);
  assert(host_obj.section_by_name(&host_obj, ".text", &idx, &shdr)
         == ELF_SUCCESS);
  assert(idx == 2);
  assert(shdr->sh_offset == 0x64);
  assert(shdr->sh_size == 0x12d0);
  assert(host_obj.get_shdr(&host_obj, &host_shdr) == ELF_SUCCESS);
  shdr_old = host_shdr;
  shdr_off_old = host_ehdr->e_shoff;
  shdr_after = shdr;
  // save all old values to enable us to compare them later
  while (host_obj.section_after_offset(&host_obj, shdr_after->sh_offset,
        &shdr_after, &idx_after) == ELF_SUCCESS) {
    shdr_after_old[idx_after] = shdr_after;
    num_sec_after--;
  }
  // Make sure we count all of them
  assert(num_sec_after == 0);
  // Now do the actual move
  assert(host_obj.section_move_back(&host_obj, idx, shift) == ELF_SUCCESS);
  // Make sure the actual section has shifted
  assert(host_obj.get_shdr(&host_obj, &host_shdr) == ELF_SUCCESS);
  assert((uint8_t *)host_shdr == ((uint8_t *)shdr_old) + shift);
  // Now verify that all sections behind it also moved
  assert(host_obj.section_by_name(&host_obj, ".text", &idx, &shdr)
         == ELF_SUCCESS);
  shdr_after = shdr;
  while (host_obj.section_after_offset(&host_obj, shdr_after->sh_offset,
        &shdr_after, &idx_after) == ELF_SUCCESS) {
    assert(((uint8_t *)shdr_after_old[idx_after]) + shift ==
        ((uint8_t *)shdr_after));
    num_sec_after++;
  }
  // Make sure we checked all sections after this one
  assert(num_sec_after == 21);
  // Finally check that the shdr moved if they were behind the section
  assert(host_ehdr->e_shoff == shdr_off_old + shift);
}

void test_move_shdr(void) {
  Elf_Ehdr *parasite_ehdr;
  Elf_Shdr *shdr_after, *shdr_old, *parasite_shdr;
  Elf_Word idx_after, shoff, shift = 1337, section_off_old;

  assert(parasite_obj.get_ehdr(&parasite_obj, &parasite_ehdr) == ELF_SUCCESS);
  assert(parasite_obj.get_shdr(&parasite_obj, &parasite_shdr) == ELF_SUCCESS);
  assert(elf_enlarge_obj(&parasite_obj, shift) == ELF_SUCCESS);
  assert(parasite_obj.section_after_offset(&parasite_obj,
        parasite_ehdr->e_shoff, &shdr_after, &idx_after) == ELF_SUCCESS);
  // save the old pointers to check later
  shdr_old = parasite_shdr;
  shoff = parasite_ehdr->e_shoff;
  section_off_old = shdr_after->sh_offset;
  assert(idx_after == 3);
  assert(shdr_after->sh_offset == 0x2ba8);
  // now move shdrs
  assert(elf_move_shtab_back(&parasite_obj, shift) == ELF_SUCCESS);
  // check it has actually moved
  assert(parasite_ehdr->e_shoff == shoff + shift);
  assert(parasite_obj.get_shdr(&parasite_obj, &parasite_shdr) == ELF_SUCCESS);
  assert(parasite_shdr == (Elf_Shdr *)((uint8_t *)shdr_old + shift));
  // check if the section behind it also moved
  assert(parasite_obj.section_after_offset(&parasite_obj,
        parasite_ehdr->e_shoff, &shdr_after, &idx_after) == ELF_SUCCESS);
  assert(shdr_after->sh_offset == section_off_old + shift);
}

void test_inject_section(void) {
  Elf_Ehdr *ehdr;
  Elf_Shdr *shdr, *shdr_dst;
  Elf_Word idx, idx_dst;
  uint8_t *buf;
  char *name;
  Elf_Off old_file_end;

  assert(host_obj.get_ehdr(&host_obj, &ehdr) == ELF_SUCCESS);
  old_file_end = ehdr->e_shoff + ehdr->e_shnum * ehdr->e_shentsize;
  assert(parasite_obj.section_by_name(&parasite_obj, ".text", &idx, &shdr)
      == ELF_SUCCESS);
  assert(parasite_obj.section_get_contents(&parasite_obj, shdr, &buf)
      == ELF_SUCCESS);
  assert(buf == parasite_obj.data + shdr->sh_offset);
  assert(idx == 2);
  assert(shdr->sh_offset == 0x64);
  assert(parasite_obj.section_get_name(&parasite_obj, shdr, &name)
      == ELF_SUCCESS);
  assert(strcmp(name, ".text") == 0);
  assert(elf_inject_section(&host_obj, &parasite_obj, buf, shdr->sh_size, shdr,
      idx, name, &idx_dst) == ELF_SUCCESS);
  assert(idx_dst == 25);
  assert(host_obj.section_by_idx(&host_obj, idx_dst, &shdr_dst) == ELF_SUCCESS);
  // The new section should be at the previous end of the file
  // (before manipulation), plus size of the name, a new shdr and a
  // new symtab entry. Name is prepended with .pmem and appended a zero byte.
  assert(shdr_dst->sh_offset == old_file_end + strlen(name) + strlen(".pmem")
      + 1 + sizeof(Elf_Shdr) + sizeof(Elf_Sym));
}

void test_find_rela(void) {
  Elf_Shdr *shdr, *rela;
  Elf_Word idx, rela_idx;

  assert(parasite_obj.section_by_name(&parasite_obj, ".text", &idx, &shdr)
      == ELF_SUCCESS);
  assert(shdr->sh_offset == 0x64);
  assert(idx == 2);
  assert(parasite_obj.relocation_to_section(&parasite_obj, idx, &rela,
        &rela_idx) == ELF_SUCCESS);
  assert(rela_idx == 3);
  assert(rela->sh_offset == 0x2ba8);
}

void test_inject_obj(void) {
  assert(elf_inject_obj(&host_obj, &parasite_obj, ".pmem") == ELF_SUCCESS);
}

void utest_summary(void) {
  if (current_test == passed_tests) {
    puts("ALL TESTS PASSED");
  } else {
    printf("%d TESTS FAILED\n", current_test - passed_tests);
    if (elf_to_file(out_path, &host_obj) == ELF_SUCCESS) {
      printf("Dumped resulting module to file '%s'\n", out_path);
    } else {
      printf("Failed to dump resulting module\n");
    }
  }
}

int main(int argc, char **argv) {
  (void)argc;
  (void)argv;

  init_tests();
  utest_run("creating a new elf object from file", test_read_obj());
  utest_run("creating a new elf object from memory", test_read_obj_from_mem());
  utest_run("validating object pointers", test_pointer_invalid());
  utest_run("parsing elf headers", test_parse_headers());
  utest_run("multiple ways of getting symbols", test_get_symbol());
  utest_run("getting symbol names", test_get_symbol_name());
  utest_run("multiple ways of getting sections", test_get_section());
  utest_run("checking if section is in front of shdr", test_shdrtab_is_next());
  utest_run("checking if there are sections behind others",
            test_get_section_after());
  utest_run("moving shdr in file", test_move_shdr());
  reset_tests();
  utest_run("moving sections around in file", test_move_section());
  reset_tests();
  utest_run("growing sections in size", test_enlarge_section());
  reset_tests();
  utest_run("inserting entries into string table", test_insert_strtab());
  reset_tests();
  utest_run("adding a shdr entry", test_add_shdr());
  reset_tests();
  utest_run("finding rela to section", test_find_rela());
  reset_tests();
  utest_run("inject section", test_inject_section());
  reset_tests();
  utest_run("injecting entire elf object", test_inject_obj());
  utest_summary();
  cleanup_tests();

  return EXIT_SUCCESS;
}
