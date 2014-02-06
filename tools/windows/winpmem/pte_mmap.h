// Directly manipulates the page tables to map physical memory into the kernel.
// Notice: This is only an abstract base class and cannot be used standalone.
// Use the actual implementation for your operating system (eg. pte_mmap_linux).
//
// Copyright 2012 Google Inc. All Rights Reserved.
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

#ifndef _REKALL_DRIVER_PTE_MMAP_H_
#define _REKALL_DRIVER_PTE_MMAP_H_

#define PFN_TO_PAGE(pfn) (pfn << PAGE_SHIFT)
#define PAGE_TO_PFN(pfn) (pfn >> PAGE_SHIFT)

typedef unsigned __int64 pte_uint64;

#pragma pack(push, 1)
typedef union CR3_ {
  pte_uint64 value;
  struct {
    pte_uint64 ignored_1     : 3;
    pte_uint64 write_through : 1;
    pte_uint64 cache_disable : 1;
    pte_uint64 ignored_2     : 7;
    pte_uint64 pml4_p        :40;
    pte_uint64 reserved      :12;
  };
} PTE_CR3;

typedef union VIRT_ADDR_ {
  pte_uint64 value;
  void *pointer;
  struct {
    pte_uint64 offset        : 12;
    pte_uint64 pt_index      :  9;
    pte_uint64 pd_index      :  9;
    pte_uint64 pdpt_index    :  9;
    pte_uint64 pml4_index    :  9;
    pte_uint64 reserved      : 16;
  };
} VIRT_ADDR;

typedef pte_uint64 PHYS_ADDR;

typedef union PML4E_ {
  pte_uint64 value;
  struct {
    pte_uint64 present        : 1;
    pte_uint64 rw             : 1;
    pte_uint64 user           : 1;
    pte_uint64 write_through  : 1;
    pte_uint64 cache_disable  : 1;
    pte_uint64 accessed       : 1;
    pte_uint64 ignored_1      : 1;
    pte_uint64 reserved_1     : 1;
    pte_uint64 ignored_2      : 4;
    pte_uint64 pdpt_p         :40;
    pte_uint64 ignored_3      :11;
    pte_uint64 xd             : 1;
  };
} PML4E;

typedef union PDPTE_ {
  pte_uint64 value;
  struct {
    pte_uint64 present        : 1;
    pte_uint64 rw             : 1;
    pte_uint64 user           : 1;
    pte_uint64 write_through  : 1;
    pte_uint64 cache_disable  : 1;
    pte_uint64 accessed       : 1;
    pte_uint64 dirty          : 1;
    pte_uint64 page_size      : 1;
    pte_uint64 ignored_2      : 4;
    pte_uint64 pd_p           :40;
    pte_uint64 ignored_3      :11;
    pte_uint64 xd             : 1;
  };
} PDPTE;

typedef union PDE_ {
  pte_uint64 value;
  struct {
    pte_uint64 present        : 1;
    pte_uint64 rw             : 1;
    pte_uint64 user           : 1;
    pte_uint64 write_through  : 1;
    pte_uint64 cache_disable  : 1;
    pte_uint64 accessed       : 1;
    pte_uint64 dirty          : 1;
    pte_uint64 page_size      : 1;
    pte_uint64 ignored_2      : 4;
    pte_uint64 pt_p           :40;
    pte_uint64 ignored_3      :11;
    pte_uint64 xd             : 1;
  };
} PDE;

typedef union PTE_ {
  pte_uint64 value;
  VIRT_ADDR vaddr;
  struct {
    pte_uint64 present        : 1;
    pte_uint64 rw             : 1;
    pte_uint64 user           : 1;
    pte_uint64 write_through  : 1;
    pte_uint64 cache_disable  : 1;
    pte_uint64 accessed       : 1;
    pte_uint64 dirty          : 1;
    pte_uint64 pat            : 1;
    pte_uint64 global         : 1;
    pte_uint64 ignored_1      : 3;
    pte_uint64 page_frame     :40;
    pte_uint64 ignored_3      :11;
    pte_uint64 xd             : 1;
  };
} PTE;
#pragma pack(pop)

// Loglevels to exclude debug messages from production builds.
typedef enum PTE_LOGLEVEL_ {
  PTE_ERR = 0,
  PTE_LOG,
  PTE_DEBUG
} PTE_LOGLEVEL;

// The default loglevel for this build
#define PTE_BUILD_LOGLEVEL PTE_LOG

// Operating system independent error checking.
typedef enum PTE_STATUS_ {
  PTE_SUCCESS = 0,
  PTE_ERROR,
  PTE_ERROR_HUGE_PAGE,
  PTE_ERROR_RO_PTE
} PTE_STATUS;

// Functions and data for directly manipulating the page tables.
// Create an object of this type by mallocing some memory and then calling
// pte_mmap_init() on it.
typedef struct PTE_MMAP_OBJ_ {
  // this pointer.
  struct PTE_MMAP_OBJ_ *self;
  // Public
  PTE_STATUS (*remap_page)(struct PTE_MMAP_OBJ_ *self, PHYS_ADDR target);
  // Private
  void *(*get_rogue_page_)(void);
  void (*free_rogue_page_)(void *page);
  void *(*phys_to_virt_)(PHYS_ADDR addr);
  PTE_STATUS (*find_pte_)(struct PTE_MMAP_OBJ_ *self, void *vaddr, PTE **pte);
  void (*flush_tlbs_page_)(void *page);
  PTE_CR3 (*get_cr3_)(void);
  void (*log_print_)(struct PTE_MMAP_OBJ_ *self, PTE_LOGLEVEL loglevel,
                     const char *fmt, ...);
  void (*print_pte_)(struct PTE_MMAP_OBJ_ *self, PTE_LOGLEVEL loglevel,
                     PTE *pte);
  // Internal Attributes
  VIRT_ADDR rogue_page;
  PTE *rogue_pte;
  PHYS_ADDR original_addr;
  PTE_LOGLEVEL loglevel;
} PTE_MMAP_OBJ;

// Initializer for newly created objects.
void pte_mmap_init(PTE_MMAP_OBJ *self);
// Call this before freeing obj or the rogue_page.
// Will reset the page table entry for the rogue page.
void pte_mmap_cleanup(PTE_MMAP_OBJ *self);

#endif  // _REKALL_DRIVER_PTE_MMAP_H_
