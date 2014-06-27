// Subclass of the pte_mmap module. Contains implementations for the Linux
// specific part of the module.
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

#include <asm/io.h>
#include <linux/module.h>
#include <linux/smp.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>

#include "debug.h"
#include "pte_mmap_linux.h"

/* Dummy buffer for pte remapping. This has to be 2 pages so we are guaranteed
 * to have at least one complete page in this buffer, so we don't affect other
 * data items when remapping the pte. */
static unsigned char rogue_buf[2 * PAGE_SIZE];
/* We don't want to use the memory allocation APIs so the pte_mmap object has to
 * live in the data segment.
 */
PTE_MMAP_OBJ self;

// Get a free, non-paged page of memory.
static void *pte_get_rogue_page(void) {
  // return the start of the next page boundary of the rogue_buf.
  // As long as it's at least 2 pages big, the whole page is guaranteed to
  // still be in the buffer.
  return (void *)(((unsigned long)rogue_buf + PAGE_SIZE) & PAGE_MASK);
}

// The minimal version of pmem keeps the rogue page in the data segment so this
// is a nop. We still keep it for compatibility reasons, though..
static void pte_free_rogue_page(void *page) {
  return;
}

// Makes use of the fact that the page tables are always mapped in the direct
// Kernel memory map. This will not work for every address, only for directly
// mapped ones as it's basically a macro adding __PAGE_OFFSET.
static void *pte_phys_to_virt(PHYS_ADDR address) {
  return phys_to_virt(address);
}

// Flushes the tlb entry for a specific page.
static void pte_flush_tlb_page(void *addr) {
  __asm__ __volatile__("invlpg (%0);"
                       :
                       : "r"(addr)
                       : );
}

// Flushes all L1/L2/... etc. caches
static void pte_flush_caches(void) {
  __asm__ __volatile__("wbinvd;" : : );
}

// Idle a bit to give caches a chance to flush
void pte_busy_wait(PTE_MMAP_OBJ *self, size_t n) {
  int i,j;

  self->log_print_(self, PTE_DEBUG, "Spinning for %ld cycles", n);
  for (i = 0; i < n; i++) {
    j = i;
  }
}

// Return the contents of the CR4 register
CR4 pte_get_cr4(void) {
  CR4 cr4;
  __asm__ __volatile__("movq %%cr4, %%rax;"
                       "movq %%rax, %0;"
                       :"=r"(cr4)
                       :
                       :"rax");
  return cr4;
}

// Set the contents of the CR4 register
void pte_set_cr4(CR4 cr4) {
  __asm__ __volatile__("movq %0, %%rax;"
                       "movq %%rax, %%cr4;"
                       :
                       :"r"(cr4)
                       :"rax");
}

// Will clear the interrupt flag so the current thread can not be preempted.
void pte_disable_interrupts(void) {
  __asm__ __volatile__("cli");
}

// Restores the interrupt flag to re-enable preemption.
void pte_enable_interrupts(void) {
  __asm__ __volatile__("sti");
}

/* Get the contents of the CR3 register. */
static CR3 pte_get_cr3(void) {
  CR3 cr3;
  __asm__ __volatile__("mov %%cr3, %0;": "=r"(cr3.value));
  return cr3;
}

// Print messages to the kernel msg ring buffer. This can't be varargs anymore
// because we don't want to depend on vprinkt.
static void pte_log_print(PTE_MMAP_OBJ *self, PTE_LOGLEVEL loglevel,
                          const char *fmt, unsigned long arg) {
  if (self->loglevel < loglevel) {
    return;
  }
  if (loglevel == PTE_ERR) {
      DEBUG_LOG("PTE MMAP Error: ");
  }
  if (arg) {
    DEBUG_LOG(fmt, arg);
  } else {
    DEBUG_LOG(fmt);
  }
  DEBUG_LOG("\n");
}

// Initializer that fills an operating system specific vtable,
// allocates memory, etc.
PTE_MMAP_OBJ *pte_mmap_linux_new(void) {
  // Let the superconstructor set up the internal stuff
  pte_mmap_init(&self);
  // Fill the virtual function into the vtable
  self.get_rogue_page_ = pte_get_rogue_page;
  self.free_rogue_page_ = pte_free_rogue_page;
  self.phys_to_virt_ = pte_phys_to_virt;
  self.flush_tlb_page_ = pte_flush_tlb_page;
  self.flush_caches_ = pte_flush_caches;
  self.busy_wait_ = pte_busy_wait;
  self.get_cr3_ = pte_get_cr3;
  self.get_cr4_ = pte_get_cr4;
  self.set_cr4_ = pte_set_cr4;
  self.disable_interrupts_ = pte_disable_interrupts;
  self.enable_interrupts_ = pte_enable_interrupts;
  self.log_print_ = pte_log_print;
  // Initialize attributes that rely on memory allocation
  self.rogue_page.pointer = self.get_rogue_page_();
  self.log_print_(&self, PTE_DEBUG, "Looking up PTE for rogue page: %p",
                  self.rogue_page.value);
  if (self.find_pte_(&self, self.rogue_page.pointer, &(self.rogue_pte))) {
    self.log_print_(&self, PTE_ERR,
                     "Failed to find the PTE for the rogue page, "
                     "might be inside huge page, aborting...", 0);
    goto error;
  }
  self.log_print_(&self, PTE_DEBUG, "Found rogue pte at %p", self.rogue_pte->value);
  // Back up the address this pte points to for cleaning up later.
  self.original_addr = PFN_TO_PAGE(self.rogue_pte->page_frame);

  return &self;

error:
  pte_mmap_linux_delete(&self);
  return NULL;
}

// Will reset the page table entry for the rogue page.
void pte_mmap_linux_delete(PTE_MMAP_OBJ *self) {
  pte_mmap_cleanup(self);
}
