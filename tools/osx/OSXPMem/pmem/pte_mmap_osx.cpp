// Subclass of the pte_mmap module, contains OSX specific implementation.
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
//

#include "pte_mmap_osx.h"

#include <IOKit/IOLib.h>
#include <IOKit/IOMemoryDescriptor.h>
#include <stdarg.h>

// Get a free, non-paged page of memory.
static void *pte_get_rogue_page(void) {
  void *rogue_page = IOMallocAligned(PAGE_SIZE, PAGE_SIZE);
  memset(rogue_page, 0xFF, PAGE_SIZE);

  return rogue_page;
}

// Frees a single page allocated with vmalloc().
static void pte_free_rogue_page(void *page) {
  IOFreeAligned(page, PAGE_SIZE);
  return;
}

// Makes use of the fact that the page tables are allways mapped in the direct
// Kernel memory map.
static void *pte_phys_to_virt(PHYS_ADDR pa) {
  static IOMemoryDescriptor *page_desc = NULL;
  static IOMemoryMap *page_map = NULL;

  // Freeing these objects destroys the created mapping, so we have to keep a
  // reference around until the next call.
  if (page_desc != NULL) {
    page_desc->release();
    page_desc = NULL;
  }
  if (page_map != NULL) {
    page_map->release();
    page_map = NULL;
  }

  page_desc = (
      IOMemoryDescriptor::withPhysicalAddress(pa, PAGE_SIZE, kIODirectionIn));
  page_map = (
        page_desc->createMappingInTask(kernel_task, 0, kIODirectionIn, 0, 0));
  return reinterpret_cast<void *>(page_map->getAddress());
}

// Flushes the tlb entry for a specific page.
static void pte_flush_tlb_page(void *addr) {
  __asm__ __volatile__("invlpg (%0);"
                       :
                       :"r"(addr)
                       : );
}

// Flush a specific page from all cpus by sending an ipi.
static void pte_flush_all_tlbs_page(void *page) {
  // OSX does not export Inter Processor Interrupts to kernel extensions.
  // remap_page should be called from a cpu locked context or with preemption
  // disabled.
  pte_flush_tlb_page(page);
}

/* Get the contents of the CR3 register. */
static CR3 pte_get_cr3(void) {
  CR3 cr3;
  __asm__ __volatile__("mov %%cr3, %0;": "=r"(cr3.value));
  return cr3;
}

// Print messages to the kernel msg ring buffer.
static void pte_log_print(PTE_MMAP_OBJ *self, PTE_LOGLEVEL loglevel,
                          const char *fmt, ...) {
  va_list argptr;

  if (self->loglevel < loglevel) {
    return;
  }
  if (loglevel == PTE_ERR) {
      printf("PTE MMAP Error: ");
  }

  va_start(argptr, fmt);
  vprintf(fmt, argptr);
  va_end(argptr);
  printf("\n");
}

// Initializer that fills an operating system specific vtable,
// allocates memory, etc.
PTE_MMAP_OBJ *pte_mmap_osx_new(void) {
  PTE_MMAP_OBJ *self = NULL;

  self = reinterpret_cast<PTE_MMAP_OBJ *>(IOMalloc(sizeof(PTE_MMAP_OBJ)));
  // Kernel allocations should not fail but better safe than sorry...
  if (self == NULL) {
    return NULL;
  }
  // Let the superconstructor set up the internal stuff
  pte_mmap_init(self);
  // Fill the virtual function into the vtable
  self->get_rogue_page_ = pte_get_rogue_page;
  self->free_rogue_page_ = pte_free_rogue_page;
  self->phys_to_virt_ = pte_phys_to_virt;
  self->flush_tlbs_page_ = pte_flush_all_tlbs_page;
  self->get_cr3_ = pte_get_cr3;
  self->log_print_ = pte_log_print;
  // Initialize attributes that rely on memory allocation
  self->rogue_page.pointer = self->get_rogue_page_();
  self->log_print_(self, PTE_DEBUG, "Looking up PTE for rogue page: %p",
                   self->rogue_page);
  if (self->find_pte_(self, self->rogue_page.pointer, &self->rogue_pte)) {
    self->log_print_(self, PTE_ERR,
                     "Failed to find the PTE for the rogue page, "
                     "might be inside huge page, aborting...");
    goto error;
  }
  self->log_print_(self, PTE_DEBUG, "Found rogue pte at %p", self->rogue_pte);
  // Back up the address this pte points to for cleaning up later.
  self->original_addr = PFN_TO_PAGE(self->rogue_pte->page_frame);

  return self;

error:
  pte_mmap_osx_delete(self);
  return NULL;
}

// Will reset the page table entry for the rogue page and free the object.
void pte_mmap_osx_delete(PTE_MMAP_OBJ *self) {
  pte_mmap_cleanup(self);
  IOFree(self, sizeof(PTE_MMAP_OBJ));
}
