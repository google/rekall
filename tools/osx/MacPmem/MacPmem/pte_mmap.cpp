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
#include "safety.h"
#include "i386_ptable.h"
#include "i386_ptable_log.h"

#include <kern/task.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOMemoryDescriptor.h>
#include <mach/mach_vm.h>

// The headers don't include this, so this is just copied from vm internals.
#define SUPERPAGE_SIZE (2*1024*1024)

// Used to pad reads with zeros when necessary. Allocated in pmem_pte_init.
static char *zero_page = 0;

// This extern totally exists and kxld will find it, even though it's
// technically part of the unsupported kpi and not in any headers. If Apple
// eventually ends up not exporting this symbol we'll just have to get the
// kernel map some other way (probably from the kernel_task).
extern vm_map_t kernel_map;


////////////////////////////////////////////////////////////////////////////////
// MARK: Hackish kernel routines to read/write physical memory
////////////////////////////////////////////////////////////////////////////////

// All the below two routines do is use physmap (kernel private) to find the
// virtual address and write up to 8 bytes to it. The functions themselves are
// not in the headers, but the kernel _does_ export them (at least as of 10.8
// and later) so the linker will patch them in.
//
// What we should be doing is parsing the export tables or the DWARF stream to
// get these and patch them in ourselves (because what could possibly go wrong)
// but we're not quite there yet.

#ifdef PMEM_LEGACY

// The more modern phys read/write routines weren't exported by the kernel
// until 10.8, so we have to hack together our own implementation.
extern "C" {

// Even though the type is vm_offset_t, this is actually a physical address.
// This basically relies on the fact that, while addr64_t is always 64bit,
// vm_offset_t will be 32bit on old architectures, allowing the legacy code
// using this routines to continue doing what it was doing. This was apparently
// still a concern in 2011.
extern unsigned int ml_phys_read(vm_offset_t);
extern void ml_phys_write(vm_offset_t, unsigned int data);
}

static unsigned long long ml_phys_read_double_64(addr64_t paddr) {
    unsigned long long result;

    result = ml_phys_read(paddr + 4);
    result = result << 32;
    result += ml_phys_read(paddr);
    return result;
}

static void ml_phys_write_double_64(addr64_t paddr64,
                                    unsigned long long data) {
    ml_phys_write(paddr64 + 4, (unsigned) data);
    ml_phys_write(paddr64, (unsigned) (data >> 32));
}

#else

// Where possible, use the actual kernel routines.
extern "C" {
extern unsigned long long ml_phys_read_double_64(addr64_t paddr);
extern void ml_phys_write_double_64(addr64_t paddr64, unsigned long long data);
}

#endif


////////////////////////////////////////////////////////////////////////////////
// MARK: Finding and parsing paging structures
////////////////////////////////////////////////////////////////////////////////

// Flush this page's TLB.
static void pmem_pte_flush_tlb(vm_address_t page) {
    __asm__ __volatile__ ("invlpg (%0);" ::"r" (page) :);
}

// Keeps track of a rogue page, and its original paging structure.
typedef struct _pmem_pte_mapping {
    addr64_t paddr;
    vm_address_t vaddr;
    vm_size_t pagesize;
    union {
        struct {
            addr64_t pte_addr;
            PTE orig_pte;
        };
        struct {
            addr64_t pde_addr;
            PDE orig_pde;
        };
    };
} pmem_pte_mapping;


// Reads the PML4E for the 'page' virtual address.
//
// Arguments:
//   page: virtual address of the address whose PML4E is wanted.
//     page-aligned automatically.
//   pml4e: If provided, the PML4E struct is copied here.
//   pml4e_phys: If provided, the physical address of the PML4E is copied here.
//
// Returns:
//   KERN_SUCCESS or KERN_FAILURE.
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
    pmem_log_CR3(cr3, kPmemDebug, "Dumped CR3");

    entry_paddr = PFN_TO_PAGE(cr3.pml4_p) + (vaddr.pml4_index * sizeof(PML4E));

    pmem_debug("PML4E for vaddr %#016lx is at physical address %#016llx.",
               page, entry_paddr);

    if (pml4e) {
        // ml_phys_* can only succeed or panic, there are no recoverable errors.
        pml4e->value = ml_phys_read_double_64(entry_paddr);
    }

    pmem_log_PML4E(*pml4e, kPmemDebug, "for vaddr");

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
        pmem_warn("PDE %u of vaddr %#016llx is for a huge (2 MB) page.",
                   vaddr.pd_index, vaddr.value);
        pmem_log_PDE(pde, kPmemWarn, "Offending PDE.");
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
kern_return_t pmem_write_pte(addr64_t pte_phys, PTE *pte) {
    ml_phys_write_double_64(pte_phys, pte->value);
    return KERN_SUCCESS;
}


// See pmem_write_pte.
kern_return_t pmem_write_pde(addr64_t pde_phys, PDE *pde) {
    ml_phys_write_double_64(pde_phys, pde->value);
    return KERN_SUCCESS;
}

////////////////////////////////////////////////////////////////////////////////
// MARK: Page mapping lifecycle
////////////////////////////////////////////////////////////////////////////////

// Creates a new (non-global) rogue page mapped to paddr.
//
// Arguments:
//  paddr: The desired physical page. Must be aligned.
//  mapping: If successful, mapping->vaddr will contain a virtual address
//      mapped to paddr, of size mapping->pagesize. After being used, this
//      mapping must be passed to pmem_pte_destroy_mapping to be cleaned up.
//
// Notes:
//  Currently, only 4K pages are used. 2MB page support will be added in the
//  future.
//
// Returns: KERN_SUCCESS or KERN_FAILURE.
kern_return_t pmem_pte_create_mapping(addr64_t paddr,
                                      pmem_pte_mapping *mapping) {
    kern_return_t error = KERN_FAILURE;
    int flags = VM_FLAGS_ANYWHERE;

#if PMEM_USE_LARGE_PAGES
    mapping->pagesize = SUPERPAGE_SIZE_2MB;
#else
    mapping->pagesize = PAGE_SIZE;
#endif

    error = vm_allocate(kernel_map, &mapping->vaddr, mapping->pagesize, flags);

    if (error != KERN_SUCCESS) {
        bzero(mapping, sizeof(pmem_pte_mapping));
        pmem_error("Could not reserve a page. Error code: %d.", error);
        return error;
    }

    // We now have a speculative page. Write to it to force a pagefault.
    // After this the paging structures will exist.
    memset((void *)mapping->vaddr, 1, sizeof(int));

    // Grab a copy of the paging structure (PTE or PDE).
#if PMEM_USE_LARGE_PAGES
    error = pmem_read_pde(mapping->vaddr, &mapping->orig_pde,
                          &mapping->pde_addr);
#else
    error = pmem_read_pte(mapping->vaddr, &mapping->orig_pte,
                          &mapping->pte_addr);
#endif

    if (error != KERN_SUCCESS) {
        bzero(mapping, sizeof(pmem_pte_mapping));
        pmem_error("Could not find the PTE or PDE for rogue page. Bailing.");
        return error;
    }

    // pmem_read_* functions already verify the paging structure is present,
    // but for PDEs we also need to ensure the size flag is set.
#if PMEM_USE_LARGE_PAGES
    if (!mapping->orig_pde.page_size) {
        pmem_error("PDE was reserved for a 2MB page, but page_size flag is "
                   "not set. Bailing.");
        bzero(mapping, sizeof(pmem_pte_mapping));
        return KERN_FAILURE;
    }
#endif

    // Now we have a page of our own and can do horrible things to it.
#if PMEM_USE_LARGE_PAGES
    PDE new_pde = mapping->orig_pde;
    new_pde.pt_p = PAGE_TO_PFN(paddr);

    pmem_write_pde(mapping->pde_addr, &new_pde);
#else
    PTE new_pte = mapping->orig_pte;
    new_pte.page_frame = PAGE_TO_PFN(paddr);

    // We absolutely want the TLB for this page flushed when switching context.
    new_pte.global = 0;

    pmem_write_pte(mapping->pte_addr, &new_pte);
    pmem_log_PTE(new_pte, kPmemDebug, "Writing PTE:");
#endif

    pmem_pte_flush_tlb(mapping->vaddr);
    return KERN_SUCCESS;
}


// Destroys a mapping created by pmme_pte_create_mapping.
//
// Arguments:
//  mapping: The paging structures of the virtual page will be restored to
//      their original values, and the page will be deallocated. The mapping
//      struct will be bzero'd.
//
// Returns:
//  KERN_SUCCESS or KERN_FAILURE.
kern_return_t pmem_pte_destroy_mapping(pmem_pte_mapping *mapping) {
    if (!mapping->vaddr) {
        return KERN_SUCCESS;
    }

#if PMEM_USE_LARGE_PAGES
    pmem_write_pde(mapping->pde_addr, &mapping->orig_pde);
#else
    pmem_write_pte(mapping->pte_addr, &mapping->orig_pte);
#endif

    kern_return_t error = vm_deallocate(kernel_map, mapping->vaddr,
                                        mapping->pagesize);

    if (error != KERN_SUCCESS) {
        pmem_error("Could not free reserved page %#016lx.", mapping->vaddr);
        return error;
    }

    bzero(mapping, sizeof(pmem_pte_mapping));
    return KERN_SUCCESS;
}


////////////////////////////////////////////////////////////////////////////////
// MARK: Public API - read handler and vtop
////////////////////////////////////////////////////////////////////////////////

// Read/write handler for /dev/pmem. Does what you'd expect.
//
// It's alright to call this for io operations that cross page boundaries.
kern_return_t pmem_readwrite_physmem(struct uio *uio) {
    kern_return_t error = KERN_SUCCESS;

    if (uio_offset(uio) < 0) {
        // Negative offsets into physical memory really make no sense. Without
        // this check, this call would just return all zeroes, but it's
        // probably better to just fail.
        return KERN_FAILURE;
    }

    user_ssize_t resid = uio_resid(uio);
    off_t offset = uio_offset(uio);

    while (resid > 0) {
        // How many bytes are we moving?
        unsigned long amount = 0;

        if (!pmem_allow_unsafe_operations &&
            !pmem_rangemap_test(safety_rangemap, offset)) {
            // This page is not readable and unsafe operations are disabled,
            // which also means we're definitely reading and not writing.
            // Instead of doing an actual read, copy zeros from the zero page
            // and call it a day.

            if (offset >
                safety_rangemap->ranges[safety_rangemap->top_range].end) {
                // We're past the end of physical memory.
                pmem_warn("Read attempted at %#016llx, which is past the end "
                          "of physical memory at %#016llx.",
                          offset,
                          safety_rangemap->
                            ranges[safety_rangemap->top_range].end);
                return KERN_FAILURE;
            }

            amount = PAGE_SIZE - (offset % PAGE_SIZE);
            uiomove(zero_page, (int)amount, uio);
        } else {
            // We are allowed to touch this page. Do actual IO.

            // We make a mapping for the whole page that offset falls into.
            pmem_pte_mapping mapping;
            error = pmem_pte_create_mapping(offset & ~PAGE_MASK, &mapping);
            if (error != KERN_SUCCESS) {
                pmem_error("Could not acquire a rogue page.");
                goto bail;
            }

            // We have a mapping - offset IO operations relative to the page
            // boundary.
            user_ssize_t in_page_offset = offset % mapping.pagesize;
            amount = MIN(resid, mapping.pagesize - in_page_offset);
            unsigned long rv = uiomove((char *)mapping.vaddr + in_page_offset,
                                       (int)amount, uio);

            if (rv != 0) {
                // If this happens, it's basically the kernel's problem.
                // All we can do is fail and log.
                pmem_error("uiomove returned %lu.", rv);
                error = KERN_FAILURE;
                goto bail;
            }

            // Mappings are ephemeral.
            error = pmem_pte_destroy_mapping(&mapping);
            if (error != KERN_SUCCESS) {
                pmem_error("Could not release a rogue page.");
                goto bail;
            }
        }

        offset += amount;
        resid = uio_resid(uio);
    }

bail:
    return error;
}


// Finds physical address corresponding to the virtual address.
//
// Arguments:
//  vaddr: The virtual address whose physical offset is desired.
//  paddr: If successful, the physical offset will be written here.
//
// Returns:
//  KERN_SUCCESS or KERN_FAILURE.
kern_return_t pmem_pte_vtop(vm_offset_t vaddr, unsigned long long *paddr) {
    kern_return_t error;

    PTE pte;
    error = pmem_read_pte(vaddr, &pte, 0);
    pmem_log_PTE(pte, kPmemDebug, "for vtop");

    if (error == KERN_SUCCESS) {
        // This returns the address of a 4K page.
        *paddr = (pte.page_frame << PAGE_SHIFT) + (vaddr % PAGE_SIZE);
        return error;
    }

    // If that failed, the page is either paged out (no phys address) or a
    // huge page.
    PDE pde;
    error = pmem_read_pde(vaddr, &pde, 0);

    if (error == KERN_SUCCESS && pde.page_size) {
        // Not SUPERPAGE_SHIFT (16) because the bit offset of the page in PD
        // and PT entries is the same (9).
        *paddr = ((pde.pt_p << PAGE_SHIFT) +
                  (vaddr % SUPERPAGE_SIZE));
    }

    // If we got here the vaddr is likely paged out (or part of a 1GB page,
    // which is currently unlikely.)
    return error;
}


////////////////////////////////////////////////////////////////////////////////
// MARK: Init and teardown
////////////////////////////////////////////////////////////////////////////////

kern_return_t pmem_pte_init() {
    zero_page = (char *)OSMalloc(PAGE_SIZE, pmem_alloc_tag);

    if (!zero_page) {
        pmem_fatal("Could not allocate the zero page.");
        return KERN_FAILURE;
    }

    bzero(zero_page, PAGE_SIZE);

    return KERN_SUCCESS;
}


void pmem_pte_cleanup() {
    if (zero_page) {
        OSFree(zero_page, PAGE_SIZE, pmem_alloc_tag);
        zero_page = 0;
    }
}
