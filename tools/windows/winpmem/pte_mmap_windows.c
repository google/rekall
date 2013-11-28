// Subclass of the pte_mmap module. Contains implementations for the Windows
// specific part of the module.
//
// Copyright 2012 Google Inc. All Rights Reserved.
// Author: Johannes Stüttgen (johannes.stuettgen@gmail.com)
// Author: Michael Cohen (scudette@gmail.com)
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

#include "pte_mmap_windows.h"

static char rogue_page[PAGE_SIZE * 3] = "";
static char *page_aligned_space = NULL;
static MDL *rogue_mdl = NULL;


// Get a free, non-paged page of memory. On windows we can not
// allocate from pool because pool storage is controlled by large page
// PTEs. So we just use a static page in the driver executable.
static void *pte_get_rogue_page(void) {
  if (page_aligned_space == NULL) {
    rogue_mdl = IoAllocateMdl(&rogue_page, sizeof(rogue_page),
			     FALSE, FALSE, NULL);
    if (!rogue_mdl) {
      return NULL;
    };

    try {
      MmProbeAndLockPages(rogue_mdl, KernelMode, IoWriteAccess);
    } except(EXCEPTION_EXECUTE_HANDLER) {
      NTSTATUS ntStatus = GetExceptionCode();

      WinDbgPrint("Exception while locking inBuf 0X%08X in METHOD_NEITHER\n",
		  ntStatus);
      IoFreeMdl(rogue_mdl);
      rogue_mdl = NULL;
      return NULL;
    }
    page_aligned_space = rogue_page;
    page_aligned_space += PAGE_SIZE - ((__int64)rogue_page) % PAGE_SIZE;
  };

  return page_aligned_space;
}

// Frees a single page allocated with vmalloc(). Rogue page is static
// we do not free it.
static void pte_free_rogue_page(void *page) {
  if (rogue_mdl) {
    MmUnlockPages(rogue_mdl);
    IoFreeMdl(rogue_mdl);
    page_aligned_space = NULL;
    rogue_mdl = NULL;
  };
  return;
}

// Makes use of the fact that the page tables are always mapped in the direct
// Kernel memory map.
static void *pte_phys_to_virt(PHYS_ADDR address) {
  PHYSICAL_ADDRESS phys_address;

  phys_address.QuadPart = address;
  //return phys_to_virt(address);
  // TODO(scudette): Use PFNDB here.
  return Pmem_KernelExports.MmGetVirtualForPhysical(phys_address);
}

// Flushes the tlb entry for a specific page.
static void pte_flush_tlb_page(void *addr) {
  // Use compiler instrinsic.
  __invlpg(addr);
}

// Flush a specific page from all cpus by sending an ipi.
static void pte_flush_all_tlbs_page(void *page) {
  // TODO: Make this work.
  pte_flush_tlb_page(page);
}

/* Get the contents of the CR3 register. */
static PTE_CR3 pte_get_cr3(void) {
  PTE_CR3 result;
  result.value = __readcr3();
  return result;
}

// Print messages to the kernel msg ring buffer.
static void pte_log_print(PTE_MMAP_OBJ *self, PTE_LOGLEVEL loglevel,
                          const char *fmt, ...) {
  va_list argptr;

  if (self->loglevel < loglevel) {
    return;
  }

  va_start(argptr, fmt);
  vWinDbgPrintEx(DPFLTR_IHVDRIVER_ID, 14, fmt, argptr);
  va_end(argptr);
}


// Will reset the page table entry for the rogue page and free the object.
void pte_mmap_windows_delete(PTE_MMAP_OBJ *self) {
  pte_mmap_cleanup(self);
  ExFreePool(self);
}

// Initializer that fills an operating system specific vtable,
// allocates memory, etc.
PTE_MMAP_OBJ *pte_mmap_windows_new(void) {
  PTE_MMAP_OBJ *self = NULL;

  // Allocate the object
  self = ExAllocatePoolWithTag(NonPagedPool, sizeof(PTE_MMAP_OBJ),
			       PMEM_POOL_TAG);

  if (!self) return NULL;

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
  pte_mmap_windows_delete(self);
  return NULL;
}
