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

#ifndef __MacPmem__pte_mmap__
#define __MacPmem__pte_mmap__

#include <mach/mach_types.h>
#include <libkern/libkern.h>

// There is currently no real support for large pages for two reasons:
//
// Firstly, the kernel currently doesn't allow extensions to request large
// pages. This, we could work around by patching in the address of the right
// alloc routine form the kernel's DWARF symbols, (since it's not in the export
// tables) but it's obviously not ideal.
//
// Secondly, the uio system will only make reads of 4K each at most, and we
// only create mappings for the duration of the read, which means that using
// large pages, we would be creating a 2MB mapping for each 4K read which is
// obviously not helpful.
//
// As an additional caveat, read/write safety is not really compatible with PDE
// mappings, but that's just a question of refactoring. (Although it would work,
// if we let it, kind of by accident, because of how uio happens to structure
// reads.)
//
// Still, having this around is useful for testing how the code will work with
// PDEs when the above issues can be surmounted. I would not enable it for any
// build that's going to see more than experimental use, though.
#define PMEM_USE_LARGE_PAGES 0

#ifdef __cplusplus
extern "C" {
#endif

// Translate the virtual address 'vaddr' to physical address 'paddr'.
//
// Looks up and parses the hardware-dependent paging structures for the
// virtual address to determine the page frame and calculate the physical
// offset.
//
// Arguments:
//   vaddr: The virtual address to look up.
//   paddr: On success, the physical address will be written here.
//
// Returns:
//   KERN_SUCCESS if it wrote paddr, otherwise KERN_FAILURE.
kern_return_t pmem_pte_vtop(vm_offset_t vaddr, unsigned long long *paddr);

// Initialization routines - these set up some shared resources (e.g. the
// read-only zero page.
kern_return_t pmem_pte_init(void);
void pmem_pte_cleanup(void);

// Read physical memory at offset determined by the uio.
//
// This is a read handler that the device read handler delegates to. It
// allocates a page, then finds the PTE for that page and overwrites it
// to point to the physical page the uio offset lies in, then reads from it.
//
// Arguments:
//   uio: This is the structure the kernel uses for IO. See man uio.
//
// Returns:
//   KERN_SUCCESS in most cases, even if the IO operation itself was
//   zero-padded. Returns KERN_FAILURE for out of bounds, although with safety
//   off, will permit reads from ABOVE max physical memory.
kern_return_t pmem_readwrite_physmem(struct uio *uio);

#ifdef __cplusplus
}
#endif

#endif /* defined(__MacPmem__pte_mmap__) */
