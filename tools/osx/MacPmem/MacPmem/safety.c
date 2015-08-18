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

#include "safety.h"
#include "meta.h"
#include "pmem_common.h"
#include "logging.h"
#include <mach/vm_param.h>

pmem_rangemap *safety_rangemap = 0;


// Add the range to the safety rangemap if it's read-friendly.
//
// Interprets the 'range', and if it decides that it's ok to read from, will
// mark its pages are such in the 'rangemap'.
//
// Arguments:
//   range: The EFI physmap range to examine.
//   rangemap: The safety rangemap where 1 means read-friendly.
//
// Returns:
//   As expected - fails if 'range' or 'rangemap' are invalid.
static kern_return_t pmem_register_efi_range(pmem_efi_range_t *range,
                                             pmem_rangemap *rangemap) {
    if (range->start % PAGE_SIZE || range->length % PAGE_SIZE) {
        pmem_fatal("EFI range is not page-aligned: %#016llx + %#016llx.",
                   range->start, range->length);
        return KERN_FAILURE;
    }

    switch (range->efi_type) {
    // These range types cannot be read and we skip them.
    case EfiReservedMemoryType:
    case EfiUnusableMemory:
    case EfiMemoryMappedIO:
    case EfiMemoryMappedIOPortSpace:
        // We can just skip ranges we don't care about, because the rangemap
        // will automatically pad up to the next readable range.
        pmem_debug("EFI range %#016llx - %#016llx is non-readable; skipping.",
                   range->start, range->start + range->length - 1);
        return KERN_SUCCESS;

    // Other ranges are readable and we mark them as such in the rangemap.
    default:
        if (!pmem_rangemap_add(safety_rangemap,
                               range->start,
                               range->start + range->length - 1,
                               PMEM_MAP_READABLE)) {
            pmem_error("Failed to register EFI range %#016llx - %#016llx.",
                       range->start,
                       range->start + range->length - 1);
            return KERN_FAILURE;
        }
    }

    pmem_debug("Added EFI range %#016llx - %#016llx as readable.",
               range->start, range->start + range->length - 1);
    return KERN_SUCCESS;
}

kern_return_t pmem_safety_init(void) {
    kern_return_t error = KERN_FAILURE;

    // Grab the meta struct with EFI ranges and boot arguments (for memsize).
    pmem_meta_t *meta = 0;
    error = pmem_fillmeta(&meta, PMEM_INFO_LIST_PHYSMAP | PMEM_INFO_BOOTARGS);

    if (error != KERN_SUCCESS) {
        pmem_error("Failed to get a meta struct listing EFI.");
        goto bail;
    }

    // This will give the rangemap one bit per every 4K physical page. It can
    // grow if it turns out this number is wrong.
    uint64_t physical_page_count = meta->phys_mem_size / PAGE_SIZE;
    if (physical_page_count > UINT32_MAX) {
        return KERN_FAILURE;
    }
    safety_rangemap = pmem_rangemap_make((uint32_t) physical_page_count);

    if (error != KERN_SUCCESS) {
        pmem_error("Failed to allocate EFI safety rangemap.");
        goto bail;
    }

    // Iterate over the records in the meta struct and build up our rangemap.
    void *current_record = meta->records;

    pmem_debug("Discovered %u memory ranges.", meta->record_count);

    for (unsigned record_idx = 0;
         record_idx < meta->record_count;
         ++record_idx) {
        pmem_meta_record_t *record = current_record;
        if (record->type == pmem_efi_range_type) {
            error = pmem_register_efi_range(&record->efi_range,
                                            safety_rangemap);
            if (error != KERN_SUCCESS) {
                goto bail;
            }
        }

        current_record += record->size;
    }

    pmem_info("Initialized EFI range map with %u merged ranges, "
              "ending at %#016llx.",
              safety_rangemap->top_range,
              (safety_rangemap->ranges + safety_rangemap->top_range)->end);

    error = KERN_SUCCESS;

bail:
    if (meta) {
        pmem_metafree(meta);
    }

    return error;
}

void pmem_safety_cleanup(void) {
    if (safety_rangemap) {
        pmem_rangemap_destroy(safety_rangemap);
        safety_rangemap = 0;
    }
}
