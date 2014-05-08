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
  self->log_print_(self, PTE_LOG, "Remapping rogue page to: 0x%016llx", target);
  // Change the pte to point to the new offset.
  self->rogue_pte->page_frame = PAGE_TO_PFN(target);
  // Flush the old pte from the tlbs in the system.
  self->flush_tlb_page_(self->rogue_page.pointer);

  return PTE_SUCCESS;
}

// Edit the page tables to point a virtual address to a specific physical page.
//
// Args:
//  self: The this pointer to the object using this function.
//  page: The virtual address of the page to remap.
//  target: The physical address to map to.
//
// Returns:
//  PTE_SUCCESS or PTE_ERROR
//
static PTE_STATUS pte_remap_page(PTE_MMAP_OBJ *self, VIRT_ADDR page, PHYS_ADDR target) {
  PTE *pte;

  // Can only remap pages, addresses must be page aligned.
  if (((!target) & PAGE_MASK) || page.offset) {
    self->log_print_(self, PTE_ERR,
                     "Failed to map %#016llx, "
                     "only page aligned remapping is supported!",
                     target);
    return PTE_ERROR;
  }
  if (self->find_pte_(self, page.pointer, &pte)) {
    self->log_print_(self, PTE_ERR,
                     "Failed to find the PTE for the rogue page, "
                     "might be inside huge page, aborting...",0);
    return PTE_ERROR;
  }
  self->log_print_(self, PTE_LOG, "Remapping pte to %#016llx", target);
  // Change the pte to point to the new offset.
  pte->page_frame = PAGE_TO_PFN(target);
  // Disable this page being global
  pte->global = 0;
  // Flush the old pte from the tlbs in the system.
  self->flush_tlb_page_(page.pointer);
  // Flush L1/L2/L3 caches
  self->flush_caches_();

  return PTE_SUCCESS;
}

// Parse a copy of the cr4 registers contents in memory and print it.
//
// Args:
//  self: The this pointer to the object using this function.
//  loglevel: The loglevel on which to print this.
//  cr4: A pointer to the cr4 registers content in memory..
//
static void pte_print_cr4(PTE_MMAP_OBJ *self, PTE_LOGLEVEL loglevel,
                          CR4 *cr4) {
  self->log_print_(self, loglevel, "CR4:", 0);
  self->log_print_(self, loglevel, "\tvme:       %lld", (pte_uint64)cr4->vme);
  self->log_print_(self, loglevel, "\tpvi:       %lld", (pte_uint64)cr4->pvi);
  self->log_print_(self, loglevel, "\ttsd:       %lld", (pte_uint64)cr4->tsd);
  self->log_print_(self, loglevel, "\tde:        %lld", (pte_uint64)cr4->de);
  self->log_print_(self, loglevel, "\tpse:       %lld", (pte_uint64)cr4->pse);
  self->log_print_(self, loglevel, "\tpae:       %lld", (pte_uint64)cr4->pae);
  self->log_print_(self, loglevel, "\tmce:       %lld", (pte_uint64)cr4->mce);
  self->log_print_(self, loglevel, "\tpge:       %lld", (pte_uint64)cr4->pge);
  self->log_print_(self, loglevel, "\tpce:       %lld", (pte_uint64)cr4->pce);
  self->log_print_(self, loglevel, "\tosxfxsr:   %lld",
      (pte_uint64)cr4->osfxsr);
  self->log_print_(self, loglevel, "\tosxmmexcpt:%lld",
    (pte_uint64)cr4->osxmmexcpt);
  self->log_print_(self, loglevel, "\tvmxe:      %lld", (pte_uint64)cr4->vmxe);
  self->log_print_(self, loglevel, "\tsmxe:      %lld", (pte_uint64)cr4->smxe);
  self->log_print_(self, loglevel, "\tpcide:     %lld", (pte_uint64)cr4->pcide);
  self->log_print_(self, loglevel, "\tosxsave:   %lld",
    (pte_uint64)cr4->osxsave);
  self->log_print_(self, loglevel, "\tsmep:      %lld", (pte_uint64)cr4->smep);
  self->log_print_(self, loglevel, "\tsmap:      %lld", (pte_uint64)cr4->smap);
}

// Parse a 64 bit page table entry and print it.
static void pte_print_pte(PTE_MMAP_OBJ *self, PTE_LOGLEVEL loglevel,
                           PTE *pte) {
  self->log_print_(self, loglevel, "Virtual Address:%#016llx", (pte_uint64)pte);
  self->log_print_(self, loglevel, "\tpresent:      %lld",
    (pte_uint64)pte->present);
  self->log_print_(self, loglevel, "\trw:           %lld", (pte_uint64)pte->rw);
  self->log_print_(self, loglevel, "\tuser:         %lld",
    (pte_uint64)pte->user);
  self->log_print_(self, loglevel, "\twrite_through:%lld",
    (pte_uint64)pte->write_through);
  self->log_print_(self, loglevel, "\tcache_disable:%lld",
    (pte_uint64)pte->cache_disable);
  self->log_print_(self, loglevel, "\taccessed:     %lld",
    (pte_uint64)pte->accessed);
  self->log_print_(self, loglevel, "\tdirty:        %lld",
    (pte_uint64)pte->dirty);
  self->log_print_(self, loglevel, "\tpat:          %lld",
    (pte_uint64)pte->pat);
  self->log_print_(self, loglevel, "\tglobal:       %lld",
    (pte_uint64)pte->global);
  self->log_print_(self, loglevel, "\txd:           %lld",
    (pte_uint64)pte->xd);
  self->log_print_(self, loglevel, "\tpfn: %010llx",
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
  CR3 cr3;
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
                   "Resolving PTE for Address:%#016llx", vaddr.value);

  // Get contents of cr3 register to get to the PML4
  cr3 = self->get_cr3_();

  self->log_print_(self, PTE_DEBUG, "Kernel CR3 is %p", cr3.value);
  self->log_print_(self, PTE_DEBUG, "Kernel PML4 is at %p physical",
                   PFN_TO_PAGE(cr3.pml4_p));

  // Resolve the PML4
  pml4 = (PML4E *)self->phys_to_virt_(PFN_TO_PAGE(cr3.pml4_p));
  self->log_print_(self, PTE_DEBUG, "kernel PML4 is at %p virtual",
      pml4->value);

  // Resolve the PDPT
  pml4e = (pml4 + vaddr.pml4_index);

  self->log_print_(self, PTE_DEBUG, "PML4 entry at %p", pml4e->value);

  if (!pml4e->present) {

    self->log_print_(self, PTE_ERR,
                     "Error, address %#016llx has no valid mapping in PML4:",
                     vaddr.value);
    self->print_pte_(self, PTE_ERR, (PTE *)pml4e);
    goto error;
  }
  self->log_print_(self, PTE_DEBUG,
                   "PML4 entry: %p)", pml4e->value);


  pdpt = (PDPTE *)self->phys_to_virt_(PFN_TO_PAGE(pml4e->pdpt_p));
  self->log_print_(self, PTE_DEBUG, "Points to PDPT: %p)", pdpt->value);

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
                   "PDPT entry: %p)", pdpte->value);
  pd = (PDE *)self->phys_to_virt_(PFN_TO_PAGE(pdpte->pd_p));
  self->log_print_(self, PTE_DEBUG, "Points to PD:     %p)", pd->value);

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

  self->log_print_(self, PTE_DEBUG, "PD entry: %p)", pde->value);
  pt = (PTE *)self->phys_to_virt_(PFN_TO_PAGE(pde->pt_p));
  self->log_print_(self, PTE_DEBUG, "Points to PT:     %p)", pt->value);

  // Get the PTE and Page Frame
  *pte = (pt + vaddr.pt_index);
  if (! (*pte)->present) {
    self->log_print_(self, PTE_ERR,
                     "Error, address %#016llx has no valid mapping in PT:",
                     vaddr.value);
    self->print_pte_(self, PTE_ERR, (*pte));
    goto error;
  }
  self->log_print_(self, PTE_DEBUG, "PTE: %p)", (*pte)->value);

  status = PTE_SUCCESS;
error:
  return status;
}

// Finds the physical address of a mapping by parsing the page tables.
// 
// Args:
//  self: Pointer to the allocated memory for this object.
//  vaddr: The virtual address for which to find the physical.
//
// Returns: The physical address of vaddr, if it can find it, NULL otherwise.
//
// Notes: This can fail if the vaddr provided is inside a large page (>4KB). It
// won't have a PTE then.
//
// TODO: It's trivial to parse the large page entries in the page table so this
// can be extended not to fail. This is not implemented yet as we don't use
// large pages for this module yet.
//
PHYS_ADDR pte_virt_find_phys(struct PTE_MMAP_OBJ_ *self, VIRT_ADDR vaddr) {
  PTE *pte;

  if (self->find_pte_(self, vaddr.pointer, &pte)) {
    self->log_print_(self, PTE_ERR,
                     "Failed to find the PTE for the page %p, "
                     "might be inside huge page, aborting...",
                     vaddr.value);
    return 0x0000000000000000;
  }
  return pte->page_frame << PAGE_SHIFT;
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
  self->remap = pte_remap_page;
  self->find_pte_ = virt_find_pte;
  self->find_phys_ = pte_virt_find_phys;
  self->print_pte_ = pte_print_pte;
  self->print_cr4_ = pte_print_cr4;
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
