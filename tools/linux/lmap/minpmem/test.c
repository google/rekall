// This driver runs several tests on the pte_mmap object when initialized.
// You can see the success/failure of the tests by running 'dmesg'.
// Extensive debug output can be created by changing
// PTE_BUILD_LOGLEVEL to PTE_DEBUG in pte_mmap.h
//
//
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


#include <linux/module.h>
#include <linux/types.h>
#include <linux/miscdevice.h>
#include <linux/init.h>
#include <asm/page.h>
#include <asm/smp.h>
#include <linux/io.h>
#include <asm/uaccess.h>
#include <asm/types.h>
#include <asm-generic/mman-common.h>
#include <linux/thread_info.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/kallsyms.h>
#include <linux/highmem.h>
#include <asm/mmzone.h>

#include "pte_mmap_linux.h"

#define SUCCESS 0
#define WAITCYCLES 99999999
#define BUF_PAGES 10

/* To not rely on kmalloc these buffers have to come from the data segment.
 * We allocate one page more than necessary to be able to use page aligned
 * buffers. */
static unsigned char pmem_buf[(BUF_PAGES + 1) * PAGE_SIZE];

static unsigned char *pmem_get_buf_page_(unsigned long i) {
  const unsigned long buf_page = (
     ((unsigned long)pmem_buf + PAGE_SIZE) & PAGE_MASK);
  return (unsigned char *)(buf_page + (i * PAGE_SIZE));
}

// To remove dependencies this has to be implemented by us.
// This is the non-optimized libc style implementation of memcmp.
int pmem_memcmp(void *s1, void *s2, size_t n) {
  char *c1, *c2;
  int result;

  for (c1 = s1, c2 = s2, result = 0; n > 0; c1++, c2++, n--) {
    if ((result = *c1 - *c2) != 0) {
      break;
    }
  }
  return result;
}

// To remove dependencies this has to be implemented by us.
// This is the non-optimized libc style implementation of memset.
void *pmem_memset(void *s, char c, size_t n) {
  for (char *b = s; n > 0; b++, n--) {
    *b = c;
  }
	return s;
}

/* pte_mmap implementation */
PTE_MMAP_OBJ *pte_mmap;

/* Test if a single pte can be remapped successfully multiple times. */
static PTE_STATUS pmem_test_single_remap(PTE_MMAP_OBJ *pte_mmap) {
  char rogue_magic = 0xFF;
  VIRT_ADDR rogue_page;
  PHYS_ADDR buf_phys[BUF_PAGES - 1];
  VIRT_ADDR buf_virt[BUF_PAGES - 1];

  // Get one rogue page to remap and fill it with magic.
  rogue_page.pointer = pmem_get_buf_page_(0);
  pmem_memset(rogue_page.pointer, rogue_magic, PAGE_SIZE);
  // Allocate the buffers, get their physical addresses
  // and fill them with magic.
  for (int i = 1; i < BUF_PAGES; i++) {
    buf_virt[i].pointer = pmem_get_buf_page_(i);
    buf_phys[i] = pte_mmap->find_phys_(pte_mmap, buf_virt[i]);
    pmem_memset(buf_virt[i].pointer, (char)i, PAGE_SIZE);  
  }

  pte_mmap->log_print_(
      pte_mmap, PTE_DEBUG, "++++++++++++++++++++++++++++++++++++", 0);
  pte_mmap->log_print_(
      pte_mmap, PTE_DEBUG, "+ Testing pte remapping with 1 pte +", 0);
  pte_mmap->log_print_(
      pte_mmap, PTE_DEBUG, "++++++++++++++++++++++++++++++++++++", 0);
  for (int i = 1; i < BUF_PAGES; i++) {
    pte_mmap->log_print_(
        pte_mmap, PTE_DEBUG, "Rogue page contains %llx",
        *(uint64_t *)rogue_page.pointer);
    pte_mmap->log_print_(
        pte_mmap, PTE_DEBUG, "Remapping rogue page to %lx", buf_phys[i]);
    pte_mmap->remap(pte_mmap, rogue_page, buf_phys[i]);
    pte_mmap->log_print_(
        pte_mmap, PTE_DEBUG, "Rogue page contains %llx",
        *(uint64_t *)rogue_page.pointer);
    if (memcmp(rogue_page.pointer, buf_virt[i].pointer, PAGE_SIZE)) {
      pte_mmap->log_print_(pte_mmap, PTE_DEBUG, "remap %d failed!", i);
      return PTE_ERROR;
    }
  }
  return PTE_SUCCESS;
}

/* Test if multiple differend pages can each be remapped successfully once. */
static PTE_STATUS pmem_test_multi_remap(PTE_MMAP_OBJ *pte_mmap) {
  char rogue_magic = 0xFF;
  char buffer_magic = 0x00;
  // Since the buffers are unmanaged we divide them into two halves...
  unsigned int buf_start = BUF_PAGES / 2;
  VIRT_ADDR rogue_pages[BUF_PAGES / 2];
  PHYS_ADDR buf_phys[BUF_PAGES / 2];
  VIRT_ADDR buf_virt[BUF_PAGES / 2];

  // Allocate the rogue pages, buffers, get their physical addresses
  // and fill them with magic.
  for (int i = 0; i < (BUF_PAGES / 2); i++) {
    rogue_pages[i].pointer = pmem_get_buf_page_(i);
    pmem_memset(rogue_pages[i].pointer, rogue_magic - i, PAGE_SIZE);  
    buf_virt[i].pointer = pmem_get_buf_page_(buf_start + i);
    buf_phys[i] = pte_mmap->find_phys_(pte_mmap, buf_virt[i]);
    pmem_memset(buf_virt[i].pointer, buffer_magic + i, PAGE_SIZE);  
  }

  pte_mmap->log_print_(
      pte_mmap, PTE_DEBUG, "++++++++++++++++++++++++++++++++++++++++++++++", 0);
  pte_mmap->log_print_(
      pte_mmap, PTE_DEBUG, "+ Testing pte remapping with %010d ptes +",
      BUF_PAGES / 2);
  pte_mmap->log_print_(
      pte_mmap, PTE_DEBUG, "++++++++++++++++++++++++++++++++++++++++++++++", 0);
  for (int i = 0; i < (BUF_PAGES / 2); i++) {
    pte_mmap->log_print_(pte_mmap, PTE_DEBUG, "Rogue page %d", i);
    pte_mmap->log_print_(pte_mmap, PTE_DEBUG, " contains %llx",
          *(uint64_t *)rogue_pages[i].pointer);
    pte_mmap->log_print_(pte_mmap, PTE_DEBUG, "Buffer page %d", i);
    pte_mmap->log_print_(pte_mmap, PTE_DEBUG, " contains %llx",
          *(uint64_t *)buf_virt[i].pointer);
    pte_mmap->log_print_(
        pte_mmap, PTE_DEBUG, "Remapping rogue page to %lx", buf_phys[i]);
    pte_mmap->remap(pte_mmap, rogue_pages[i], buf_phys[i]);
    pte_mmap->log_print_(pte_mmap, PTE_DEBUG, "Rogue page %d", i);
    pte_mmap->log_print_(pte_mmap, PTE_DEBUG, " contains %llx",
          *(uint64_t *)rogue_pages[i].pointer);
    if (memcmp(rogue_pages[i].pointer, buf_virt[i].pointer, PAGE_SIZE)) {
      pte_mmap->log_print_(
          pte_mmap, PTE_DEBUG, "remap %d failed!", i);
      return PTE_ERROR;
    }
    pte_mmap->log_print_(pte_mmap, PTE_DEBUG, "remap %d succeeded!", i);
  }
  return PTE_SUCCESS;
}

/* Test if 2 pte's can be mapped to the same physical address. Will wait in a
 * spin lock for 'spin_count' cycles before testing.
 * This can show timing problems and if the caches are flushing correctly. */
static PTE_STATUS pmem_test_identical_remap(PTE_MMAP_OBJ *pte_mmap, size_t spin_count) {
  char page_1_magic = 0x01;
  char page_2_magic = 0x02;
  char write_magic = 0x03;
  VIRT_ADDR page_1, page_2;
  PHYS_ADDR page_1_phys, page_2_phys;

  // Allocate the buffers, get their physical addresses
  // and fill them with magic.
  page_1.pointer = pmem_get_buf_page_(0);
  page_2.pointer = pmem_get_buf_page_(1);
  page_1_phys =  pte_mmap->find_phys_(pte_mmap, page_1);
  page_2_phys =  pte_mmap->find_phys_(pte_mmap, page_2);
  memset(page_1.pointer, page_1_magic, PAGE_SIZE);  
  memset(page_2.pointer, page_2_magic, PAGE_SIZE);  
  pte_mmap->log_print_(
      pte_mmap, PTE_DEBUG, "+++++++++++++++++++++++++++++++++++++++++++++", 0);
  pte_mmap->log_print_(
      pte_mmap, PTE_DEBUG, "+ Testing remapping of 2 pte's to same page +", 0);
  pte_mmap->log_print_(
      pte_mmap, PTE_DEBUG, "+++++++++++++++++++++++++++++++++++++++++++++", 0);
  pte_mmap->log_print_(
      pte_mmap, PTE_DEBUG, "Page 1 contains %llx",
      *(uint64_t *)page_1.pointer);
  pte_mmap->log_print_(
      pte_mmap, PTE_DEBUG, "Page 2 contains %llx",
      *(uint64_t *)page_2.pointer);
  pte_mmap->log_print_(
      pte_mmap, PTE_DEBUG, "Remapping page 1 to %lx", page_2_phys);
  pte_mmap->remap(pte_mmap, page_1, page_2_phys);
  // This will occupy the cpu for a while which can cause the caches
  // (TLB/L1/L2/L3) to flush.
  // To be robust test has to be passed with spin_count of 0, but this can be
  // usefull to identify caching problems.
  if (spin_count) {
    pte_mmap->busy_wait_(pte_mmap, spin_count);
  }
  pte_mmap->log_print_(
      pte_mmap, PTE_DEBUG, "Page 1 now contains %llx",
      *(uint64_t *)page_1.pointer);
  if (memcmp(page_1.pointer, page_2.pointer, PAGE_SIZE)) {
    pte_mmap->log_print_(
        pte_mmap, PTE_DEBUG, "Remapping of page 1 to page 2 "
        "failed with spin count %d", spin_count);
    return PTE_ERROR;
  }
  // Second test determines if writes to one mapping propagate to the identical
  // second mapping. We do this by writing to mapping 2 and then comparing what
  // we read from mapping 1 to it.
  pte_mmap->log_print_(
      pte_mmap, PTE_DEBUG, "Page 1 now contains %llx",
      *(uint64_t *)page_1.pointer);
  pte_mmap->log_print_(
      pte_mmap, PTE_DEBUG, "Page 2 now contains %llx",
      *(uint64_t *)page_2.pointer);
  pmem_memset(page_2.pointer, write_magic, PAGE_SIZE);
  if (spin_count) {
    pte_mmap->busy_wait_(pte_mmap, spin_count);
  }
  pte_mmap->log_print_(
      pte_mmap, PTE_DEBUG, "Page 1 now contains %llx",
      *(uint64_t *)page_1.pointer);
  pte_mmap->log_print_(
      pte_mmap, PTE_DEBUG, "Page 1 now contains %llx",
      *(uint64_t *)page_1.pointer);
  if (pmem_memcmp(page_1.pointer, page_2.pointer, PAGE_SIZE)) {
    pte_mmap->log_print_(
        pte_mmap, PTE_DEBUG,
        "Writes to page 2 not visible from page 1"
        "despite identical mapping at spin count %d",
        spin_count);
    return PTE_ERROR;
  }
  return PTE_SUCCESS;
}

int __init test_init(void) {
  printk("---------- SNIP ----------\n");
  pte_mmap = pte_mmap_linux_new();
  if (pte_mmap == NULL) {
    printk("Failed to initialize pte mmap, unloading module\n");
    return -EFAULT;
  }
  printk("pmem test driver initialized, running tests\n");
  if (pmem_test_single_remap(pte_mmap) == PTE_SUCCESS) {
    pte_mmap->log_print_(
        pte_mmap, PTE_LOG, "[+] single remap test succeded", 0);
  } else {
    pte_mmap->log_print_(
        pte_mmap, PTE_LOG, "[-] single remap test failed!", 0);
  }
  if (pmem_test_multi_remap(pte_mmap) == PTE_SUCCESS) {
    pte_mmap->log_print_(
        pte_mmap, PTE_LOG, "[+] multi remap test succeded", 0);
  } else {
    pte_mmap->log_print_(
        pte_mmap, PTE_LOG, "[-] 2 multi remap test failed!", 0);
  }
  if (pmem_test_identical_remap(pte_mmap, WAITCYCLES) == PTE_SUCCESS) {
    pte_mmap->log_print_(
        pte_mmap, PTE_LOG, "[+] 2 page identical remap test "
        "with %d wait cycles succeded", WAITCYCLES);
  } else {
    pte_mmap->log_print_(
        pte_mmap, PTE_LOG, "[-] 2 page identical remap test "
        "with %d wait cycles failed!", WAITCYCLES);
  }
  if (pmem_test_identical_remap(pte_mmap, 0) == PTE_SUCCESS) {
    pte_mmap->log_print_(
        pte_mmap, PTE_LOG, "[+] 2 page identical remap test "
        "without wait succeded", 0);
  } else {
    pte_mmap->log_print_(
        pte_mmap, PTE_LOG, "[-] 2 page identical remap test "
        "without wait failed!", 0);
  }

  // Returning an error will unload the test module for us.
  return SUCCESS;
}

void __exit test_cleanup(void) {
  pte_mmap_linux_delete(pte_mmap);
  printk("pmem test driver unloading\n");
}

/*
module_init(pmem_init);
module_exit(pmem_cleanup_module);
*/

MODULE_LICENSE("GPL");
