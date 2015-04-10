//  MacPmem - Rekall Memory Forensics
//  Copyright (c) 2015 Google Inc. All rights reserved.
//
//  Implements the /dev/pmem device to provide read/write access to
//  physical memory.
//
//  Acknowledgments:
//   PTE remapping technique based on "Anti-Forensic Resilient Memory
//   Acquisition" (http://www.dfrws.org/2013/proceedings/DFRWS2013-13.pdf)
//   and OSXPmem reference implementation by Johannes Stüttgen.
//
//  Authors:
//   Adam Sindelar (adam.sindelar@gmail.com)
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

#include "MacPmem.h"
#include "pte_mmap.h"
#include "logging.h"
#include "meta.h"
#include "i386_ptable.h"

#include <kern/task.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOMemoryDescriptor.h>
#include <mach/mach_vm.h>


vm_address_t pmem_rogue_page = 0;
vm_size_t pmem_rogue_page_size = 0;
addr64_t pmem_rogue_pte_phys = 0;
static PTE pmem_rogue_pte;
static PTE pmem_original_pte;

static lck_mtx_t *pmem_rogue_page_mtx = nullptr;
static lck_attr_t *pmem_rogue_page_mtx_attr = nullptr;

static lck_mtx_t *pmem_rogue_pte_mtx = nullptr;
static lck_attr_t *pmem_rogue_pte_mtx_attr = nullptr;

// This extern totally exists and kxld will find it, even though it's
// technically part of the unsupported kpi and not in any headers. If Apple
// eventually ends up not exporting this symbol we'll just have to get the
// kernel map some other way (probably from the kernel_task).
extern vm_map_t kernel_map;

// More unsupported, but exported symbols we need. All these two routines do
// is basically add 'paddr' to physmap_base and dereference the result, but
// because physmap_base is private (sigh...) we have to use these for now.
extern "C" {
extern unsigned long long ml_phys_read_double_64(addr64_t paddr);
extern void ml_phys_write_double_64(addr64_t paddr64, unsigned long long data);
}

// Flush this page's TLB.
static void pmem_pte_flush_tlb(vm_address_t page) {
    __asm__ __volatile__("invlpg (%0);"::"r"(page):);
}


// Reads the PML4E for the 'page' virtual address.
//
// Arguments:
// page: virtual address of the address whose PML4E is wanted.
//       page-aligned automatically.
// pml4e: If provided, the PML4E struct is copied here.
// pml4e_phys: If provided, the physical address of the PML4E is copied here.
//
// Returns: KERN_SUCCESS or KERN_FAILURE
static kern_return_t pmem_read_pml4e(vm_address_t page, PML4E *pml4e,
                                     addr64_t *pml4e_phys) {
    VIRT_ADDR vaddr;
    vaddr.value = page;
    kern_return_t error = KERN_FAILURE;
    CR3 cr3;
    pmem_meta_t *meta = nullptr;
    addr64_t entry_paddr;

    error = pmem_fillmeta(&meta, PMEM_INFO_CR3);
    if (error != KERN_SUCCESS) {
        pmem_error("pmem_fillmeta failed to get CR3.");
        goto bail;
    }

    cr3.value = meta->cr3;
    entry_paddr = PFN_TO_PAGE(cr3.pml4_p) + (vaddr.pml4_index * sizeof(PML4E));

    pmem_debug("PML4E for vaddr %#016lx is at physical address %#016llx.",
               page, entry_paddr);

    if (pml4e) {
        // ml_phys_* can only succeed or panic, there are no recoverable errors.
        pml4e->value = ml_phys_read_double_64(entry_paddr);
    }

    if (pml4e_phys) {
        *pml4e_phys = entry_paddr;
    }

bail:
    if (meta) {
        pmem_metafree(meta);
    }

    return error;
}


// See docstring for pmem_read_pml4e.
static kern_return_t pmem_read_pdpte(vm_address_t page, PDPTE *pdpte,
                                     addr64_t *pdpte_phys) {
    VIRT_ADDR vaddr;
    vaddr.value = page;
    kern_return_t error;
    PML4E pml4e;
    addr64_t entry_paddr;

    error = pmem_read_pml4e(page, &pml4e, nullptr);
    if (error != KERN_SUCCESS) {
        return error;
    }

    if (!pml4e.present) {
        pmem_error("PML4E %u for vaddr %#016llx is not present.",
                   vaddr.pml4_index, vaddr.value);
        return KERN_FAILURE;
    }

    entry_paddr = PFN_TO_PAGE(pml4e.pdpt_p) + (vaddr.pdpt_index *sizeof(pdpte));

    pmem_debug("PDPTE for vaddr %#016lx is at physical address %#016llx.",
               page, entry_paddr);

    if (pdpte) {
        pdpte->value = ml_phys_read_double_64(entry_paddr);
    }

    if (pdpte_phys) {
        *pdpte_phys = entry_paddr;
    }

    return KERN_SUCCESS;
}


// See docstring for pmem_read_pml4e.
static kern_return_t pmem_read_pde(vm_address_t page, PDE *pde,
                                   addr64_t *pde_phys) {
    VIRT_ADDR vaddr;
    vaddr.value = page;
    kern_return_t error;
    PDPTE pdpte;
    addr64_t entry_paddr;

    error = pmem_read_pdpte(page, &pdpte, nullptr);
    if (error != KERN_SUCCESS) {
        return error;
    }

    if (!pdpte.present) {
        pmem_error("PDPTE %u of vaddr %#016llx is not present.",
                   vaddr.pdpt_index, vaddr.value);
        return KERN_FAILURE;
    }

    if (pdpte.page_size) {
        pmem_error("PDPTE %u of vaddr %#016llx is for a large (1 GB) page.",
                   vaddr.pdpt_index, vaddr.value);
        return KERN_FAILURE;
    }

    entry_paddr = PFN_TO_PAGE(pdpte.pd_p) + (vaddr.pd_index * sizeof(PDE));

    pmem_debug("PDE for vaddr %#016lx is at physical address %#016llx.",
               page, entry_paddr);

    if (pde) {
        pde->value = ml_phys_read_double_64(entry_paddr);
    }

    if (pde_phys) {
        *pde_phys = entry_paddr;
    }

    return KERN_SUCCESS;
}


// See docstring for pmem_read_pml4e.
static kern_return_t pmem_read_pte(vm_address_t page, PTE *pte,
                                   addr64_t *pte_phys) {
    VIRT_ADDR vaddr;
    vaddr.value = page;
    kern_return_t error;
    PDE pde;
    addr64_t entry_paddr;

    error = pmem_read_pde(page, &pde, nullptr);
    if (error != KERN_SUCCESS) {
        return error;
    }

    if (!pde.present) {
        pmem_error("PDE %u of vaddr %#016llx is not present.",
                   vaddr.pd_index, vaddr.value);
        return KERN_FAILURE;
    }

    if (pde.page_size) {
        pmem_error("PDE %u of vaddr %#016llx is for a huge (2 MB) page.",
                   vaddr.pd_index, vaddr.value);
        return KERN_FAILURE;
    }

    entry_paddr = PFN_TO_PAGE(pde.pt_p) + (vaddr.pt_index * sizeof(PTE));

    pmem_debug("PTE for vaddr %#016lx is at physical address %#016llx.",
               page, entry_paddr);

    if (pte) {
        pte->value = ml_phys_read_double_64(entry_paddr);
    }

    if (pte_phys) {
        *pte_phys = entry_paddr;
    }

    return KERN_SUCCESS;
}


// Overwrites the PTE at physical offset.
//
// Arguments:
// pte_phys: The physical address to overwrite. This must be a valid PTE.
// pte: The PTE struct to overwrite the address with.
//
// Returns KERN_SUCCESS. If you provide invalid values, you'll notice quickly,
// don't worry.
static kern_return_t pmem_write_pte(addr64_t pte_phys, PTE *pte) {
    ml_phys_write_double_64(pte_phys, pte->value);
    return KERN_SUCCESS;
}


// Remaps the rogue page to the physical page 'paddr'.
//
// Arguments:
// paddr: Physical page. Must be aligned.
//
// Returns: KERN_SUCCESS or KERN_FAILURE.
//
// Note:
// The only error condition is if paddr is not page-aligned. Otherwise this
// can't fail.
kern_return_t pmem_pte_map_rogue(addr64_t paddr) {
    if (!page_aligned(paddr)) {
        pmem_error("Cannot map rogue page to non-aligned address %#016llx",
                   paddr);
        return KERN_FAILURE;
    }

    lck_mtx_lock(pmem_rogue_pte_mtx);
    pmem_rogue_pte.page_frame = PAGE_TO_PFN(paddr);

    pmem_write_pte(pmem_rogue_pte_phys, &pmem_rogue_pte);
    pmem_pte_flush_tlb(pmem_rogue_page);
    lck_mtx_unlock(pmem_rogue_pte_mtx);

    return KERN_SUCCESS;
}


// Will reserve a rogue page to serve as our playtoy. This will set
// pmem_rogue_page and pmem_rogue_page_size to appropriate values. You should
// only call this if both statics are set to 0, otherwise you will leak
// memory.
//
// Args:
// pde: if true, will attempt to reserve the whole PDE to get a 2MB page.
//
// Returns KERN_SUCCESS or KERN_FAILURE.
//
// FIXME (Adam):
// The prototype of vm_allocate we're using comes from mach/mach_vm.h, but it
// looks like kxld is patching in its namesake from vm_user.c, which isn't
// great, because that routine can return KERN_INVALID_ARGUMENT if it doesn't
// like the flags. It looks like flat out asking for a superpage is one of the
// scenarios it isn't happy about. I'm fairly confident there's probably a way
// around all this, but the PDE codepath isn't a priority at the monent.
// For now, the pde flag is just disabled.
static kern_return_t pmem_reserve_page(boolean_t pde) {
    lck_mtx_lock(pmem_rogue_page_mtx);
    kern_return_t error;
    int flags = VM_FLAGS_ANYWHERE;


    if (pde) {
        pmem_rogue_page_size = SUPERPAGE_SIZE_2MB;
        flags |= VM_FLAGS_SUPERPAGE_SIZE_2MB;
    } else {
        pmem_rogue_page_size = PAGE_SIZE;
    }

    error = vm_allocate(kernel_map, &pmem_rogue_page,
                        pmem_rogue_page_size, flags);

    if (error != KERN_SUCCESS) {
        if (pde) {
            pmem_error("Could not reserve a full PDE. Error code: %d.",
                       error);
        } else {
            pmem_error("Could not reserve a rogue PTE. Error code: %d.",
                       error);
        }

        pmem_rogue_page_size = 0;
        pmem_rogue_page = 0;
    }

    // At this point the page is speculative; write to it to force a page-in.
    *((int *)pmem_rogue_page) = 1;

    // Set up the rogue PTE, and a its original value (for cleanup).
    error = pmem_read_pte(pmem_rogue_page, &pmem_original_pte,
                          &pmem_rogue_pte_phys);

    pmem_rogue_pte = pmem_original_pte;
    pmem_rogue_pte.global = 0;

    if (!pmem_rogue_pte.present) {
        pmem_error(("PTE (0x%#016llx) for reserved page %#016lx is not."
                    "present."), pmem_rogue_pte_phys, pmem_rogue_page);
        error = KERN_FAILURE;
        goto bail;
    }

bail:
    lck_mtx_unlock(pmem_rogue_page_mtx);
    return error;
}


// Read handler for /dev/pmem. Does what you'd expect.
//
// It's alright to call this for reads that cross page boundaries.
//
// NOTE: This function does absolutely no verification that the physical
// offset being read from is actually backed by conventional, or, indeed, any
// memory at all. It is the responsibility of the caller to ensure the offset
// is valid.
kern_return_t pmem_read_rogue(struct uio *uio) {
    kern_return_t error = KERN_SUCCESS;

    if (uio_offset(uio) < 0) {
        // Negative offsets into physical memory really make no sense. Without
        // this check, this call would just return all zeroes, but it's
        // probably better to just fail.
        return KERN_FAILURE;
    }

    // Only one thread can read at a time, because the rogue page is a shared
    // mutable resource that gets remapped with reads.
    lck_mtx_lock(pmem_rogue_page_mtx);

    if (!pmem_rogue_page) {
        pmem_warn("/dev/pmem got a read but rogue page isn't mapped (yet?).");
        return KERN_FAILURE;
    }

    user_ssize_t resid = uio_resid(uio);
    off_t offset = uio_offset(uio);
    unsigned long amount, rv;

    while (resid > 0) {
        pmem_pte_map_rogue(offset & ~PAGE_MASK);
        user_ssize_t page_offset = offset % pmem_rogue_page_size;
        amount = MIN(resid, pmem_rogue_page_size - page_offset);
        rv = uiomove((char *)pmem_rogue_page + page_offset, (int)amount, uio);

        if (rv != 0) {
            // If this happens, it's basically the kernel's problem.
            // All we can do is fail and log.
            pmem_error("uiomove returned %lu", rv);
            error = KERN_FAILURE;
            goto bail;
        }

        offset += amount;
        resid = uio_resid(uio);
    }

bail:
    lck_mtx_unlock(pmem_rogue_page_mtx);
    return error;
}


static void pmem_release_page(void) {
    pmem_debug("Going to release reserved page at 0x%#016lx.",
               pmem_rogue_page);

    // Grab the lock, because we want to block in case there are outstanding
    // reads still.
    lck_mtx_lock(pmem_rogue_page_mtx);

    if (!pmem_rogue_page) {
        return;
    }

    // Restore the PTE.
    pmem_write_pte(pmem_rogue_pte_phys, &pmem_original_pte);

    // Free the rogue page.
    kern_return_t error = vm_deallocate(kernel_map, pmem_rogue_page,
                                        pmem_rogue_page_size);

    if (error != KERN_SUCCESS) {
        pmem_error("Could not free reserved page %#016lx.",
                   pmem_rogue_page);
    }

    pmem_rogue_page = 0;
    pmem_rogue_page_size = 0;
    pmem_rogue_pte_phys = 0;

    lck_mtx_unlock(pmem_rogue_page_mtx);
}


kern_return_t pmem_pte_init() {
    pmem_rogue_page_mtx_attr = lck_attr_alloc_init();
    pmem_rogue_pte_mtx_attr = lck_attr_alloc_init();

#ifdef DEBUG
    lck_attr_setdebug(pmem_rogue_page_mtx_attr);
    lck_attr_setdebug(pmem_rogue_pte_mtx_attr);
#endif

    pmem_rogue_page_mtx = lck_mtx_alloc_init(pmem_mutex_grp,
                                             pmem_rogue_page_mtx_attr);
    pmem_rogue_pte_mtx = lck_mtx_alloc_init(pmem_mutex_grp,
                                            pmem_rogue_pte_mtx_attr);

    kern_return_t error = pmem_reserve_page(0);

    if (error != KERN_SUCCESS) {
        pmem_fatal("Could not reserve a rogue PTE/PDE entry.");
    } else {
        pmem_info("Reserved page @%#016lx (size 0x%lx bytes)",
                  pmem_rogue_page, pmem_rogue_page_size);
    }

    return error;
}


void pmem_pte_cleanup() {
    pmem_release_page();
    lck_mtx_free(pmem_rogue_pte_mtx, pmem_mutex_grp);
    lck_attr_free(pmem_rogue_pte_mtx_attr);

    lck_mtx_free(pmem_rogue_page_mtx, pmem_mutex_grp);
    lck_attr_free(pmem_rogue_page_mtx_attr);

}
