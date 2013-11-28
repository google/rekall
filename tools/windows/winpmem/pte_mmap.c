// This module contains helper functions to directly edit the page tables of a
// process, enabling it to map physical memory independent of the operating
// system.
//
// Warning: This code directly writes to the kernel page tables and executes
// priviledged instructions as invlpg. It will only run in ring 0.
//
//
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

#include "pte_mmap.h"

// These types are defined in OS specific headers, however to remain independent
// of them we define our own here:
#define PAGE_SHIFT 12
#define PAGE_SIZE (1ULL << PAGE_SHIFT)
#define PAGE_MASK (~(PAGE_SIZE-1))

// Edit the page tables to point a virtual address to a specific physical page.
//
// Args:
//  self: The this pointer to the object using this function.
//  target: The physical address to map to.
//
// Returns:
//  PTE_SUCCESS or PTE_ERROR
//
static PTE_STATUS pte_remap_rogue_page(PTE_MMAP_OBJ *self, PHYS_ADDR target) {
  // Can only remap pages, addresses must be page aligned.
  if (((!target) & PAGE_MASK) || self->rogue_page.offset) {
    self->log_print_(self, PTE_ERR,
                     "Failed to map %#016llx, "
                     "only page aligned remapping is supported!",
                     target);
    return PTE_ERROR;
  }
  self->log_print_(self, PTE_LOG, "Remapping pte at %p to %#016llx",
                   self->rogue_pte,
                   target);
  // Change the pte to point to the new offset.
  self->rogue_pte->page_frame = PAGE_TO_PFN(target);
  // Flush the old pte from the tlbs in the system.
  self->flush_tlbs_page_(self->rogue_page.pointer);

  return PTE_SUCCESS;
}

// Parse a 64 bit page table entry and print it.
static void print_pte_contents(PTE_MMAP_OBJ *self, PTE_LOGLEVEL loglevel,
                               PTE *pte) {
  self->log_print_(self, loglevel,
                   "Virtual Address:%#016llx\n"
                   "\tpresent:      %lld\n"
                   "\trw:           %lld\n"
                   "\tuser:         %lld\n"
                   "\twrite_through:%lld\n"
                   "\tcache_disable:%lld\n"
                   "\taccessed:     %lld\n"
                   "\tdirty:        %lld\n"
                    "\tpat:          %lld\n"
                   "\tglobal:       %lld\n"
                   "\txd:           %lld\n"
                   "\tpfn: %010llx",
                   (pte_uint64)pte,
                   (pte_uint64)pte->present,
                   (pte_uint64)pte->rw,
                   (pte_uint64)pte->user,
                   (pte_uint64)pte->write_through,
                   (pte_uint64)pte->cache_disable,
                   (pte_uint64)pte->accessed,
                   (pte_uint64)pte->dirty,
                   (pte_uint64)pte->pat,
                   (pte_uint64)pte->global,
                   (pte_uint64)pte->xd,
                   (pte_uint64)pte->page_frame);
}

// Traverses the page tables to find the pte for a given virtual address.
//
// Args:
//  self: The this pointer for the object calling this function.
//  vaddr: The virtual address to resolve the pte for
//  pte: A pointer to a pointer which will be set with the address of the pte,
//       if found.
//
// Returns:
//  PTE_SUCCESS or PTE_ERROR
//
static PTE_STATUS virt_find_pte(PTE_MMAP_OBJ *self, void *addr,
                                PTE **pte) {
  PTE_CR3 cr3;
  PML4E *pml4;
  PML4E *pml4e;
  PDPTE *pdpt;
  PDPTE *pdpte;
  PDE *pd;
  PDE *pde;
  PTE *pt;
  VIRT_ADDR vaddr;
  PTE_STATUS status = PTE_ERROR;

  vaddr.pointer = addr;

  self->log_print_(self, PTE_DEBUG,
                   "Resolving PTE for Address:%#016llx", vaddr);

  // Get contents of cr3 register to get to the PML4
  cr3 = self->get_cr3_();

  self->log_print_(self, PTE_DEBUG, "Kernel CR3 is %p", cr3);
  self->log_print_(self, PTE_DEBUG, "Kernel PML4 is at %p physical",
                   PFN_TO_PAGE(cr3.pml4_p));

  // Resolve the PML4
  pml4 = (PML4E *)self->phys_to_virt_(PFN_TO_PAGE(cr3.pml4_p));
  self->log_print_(self, PTE_DEBUG, "kernel PML4 is at %p virtual", pml4);

  // Resolve the PDPT
  pml4e = (pml4 + vaddr.pml4_index);

  self->log_print_(self, PTE_DEBUG, "PML4 entry %d is at %p", vaddr.pml4_index,
                   pml4e);

  if (!pml4e->present) {

    self->log_print_(self, PTE_ERR,
                     "Error, address %#016llx has no valid mapping in PML4:",
                     vaddr.value);
    self->print_pte_(self, PTE_ERR, (PTE *)pml4e);
    goto error;
  }
  self->log_print_(self, PTE_DEBUG,
                   "PML4[%#010x]: %p)", vaddr.pml4_index, pml4e);


  pdpt = (PDPTE *)self->phys_to_virt_(PFN_TO_PAGE(pml4e->pdpt_p));
  self->log_print_(self, PTE_DEBUG, "Points to PDPT:   %p)", pdpt);

  // Resolve the PDT
  pdpte = (pdpt + vaddr.pdpt_index);
  if (!pdpte->present) {
    self->log_print_(self, PTE_ERR,
                     "Error, address %#016llx has no valid mapping in PDPT:",
                     vaddr.value);
    self->print_pte_(self, PTE_ERR, (PTE *)pdpte);
    goto error;
  }
  if (pdpte->page_size) {
    self->log_print_(self, PTE_ERR,
                     "Error, address %#016llx belongs to a 1GB page:",
                     vaddr.value);
    self->print_pte_(self, PTE_ERR, (PTE *)pdpte);
    goto error;
  }
  self->log_print_(self, PTE_DEBUG,
                   "PDPT[%#010x]: %p)", vaddr.pdpt_index, pdpte);
  pd = (PDE *)self->phys_to_virt_(PFN_TO_PAGE(pdpte->pd_p));
  self->log_print_(self, PTE_DEBUG, "Points to PD:     %p)", pd);

  // Resolve the PT
  pde = (pd + vaddr.pd_index);
  if (!pde->present) {
    self->log_print_(self, PTE_ERR,
                     "Error, address %#016llx has no valid mapping in PD:",
                     vaddr.value);
    self->print_pte_(self, PTE_ERR, (PTE *)pde);
    goto error;
  }
  if (pde->page_size) {
    self->log_print_(self, PTE_ERR,
                     "Error, address %#016llx belongs to a 2MB page:",
                     vaddr.value);
    self->print_pte_(self, PTE_ERR, (PTE *)pde);
    goto error;
  }

  self->log_print_(self, PTE_DEBUG, "PD  [%#010x]: %p)", vaddr.pd_index, pde);
  pt = (PTE *)self->phys_to_virt_(PFN_TO_PAGE(pde->pt_p));
  self->log_print_(self, PTE_DEBUG, "Points to PT:     %p)", pt);

  // Get the PTE and Page Frame
  *pte = (pt + vaddr.pt_index);
  if (! (*pte)->present) {
    self->log_print_(self, PTE_ERR,
                     "Error, address %#016llx has no valid mapping in PT:",
                     vaddr.value);
    self->print_pte_(self, PTE_ERR, (*pte));
    goto error;
  }
  self->log_print_(self, PTE_DEBUG, "PT  [%#010x]: %p)", vaddr.pt_index, *pte);

  status = PTE_SUCCESS;
error:
  return status;
}

// Initializer for objects of this class. Takes care of the non-abstract parts
// of the object.
//
// Args:
//  self: Pointer to the allocated memory for this object.
//
void pte_mmap_init(PTE_MMAP_OBJ *self) {
  // store this pointer
  self->self = self;
  // store non-abstract functions in vtable
  self->remap_page = pte_remap_rogue_page;
  self->find_pte_ = virt_find_pte;
  self->print_pte_ = print_pte_contents;
  // Initialize attributes
  self->loglevel = PTE_BUILD_LOGLEVEL;
}

// Call this before freeing the object or the rogue_page.
// Will reset the page table entry for the rogue page.
//
// Args:
//  self: Pointer to the allocated memory for this object.
//
void pte_mmap_cleanup(PTE_MMAP_OBJ *self) {
  self->log_print_(self, PTE_DEBUG,
                   "Restoring pte to original mapping (%#016llx)",
                   self->original_addr);
  self->remap_page(self, self->original_addr);
  self->free_rogue_page_(self->rogue_page.pointer);
}
