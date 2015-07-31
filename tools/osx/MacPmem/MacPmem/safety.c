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

pmem_bitmap *safety_bitmap = 0;


// Add the range to the safety bitmap if it's read-friendly.
//
// Interprets the 'range', and if it decides that it's ok to read from, will
// mark its pages are such in the 'bitmap'.
//
// Arguments:
//   range: The EFI physmap range to examine.
//   bitmap: The safety bitmap where 1 means read-friendly.
//
// Returns:
//   As expected - fails if 'range' or 'bitmap' are invalid.
static kern_return_t pmem_register_efi_range(pmem_efi_range_t *range,
                                             pmem_bitmap *bitmap) {
    if (range->start % PAGE_SIZE || range->length % PAGE_SIZE) {
        pmem_fatal("EFI range is not page-aligned: 0x%llx + 0x%llx.",
                   range->start, range->length);
        return KERN_FAILURE;
    }

    uint64_t bits_set = 0;
    switch (range->efi_type) {
    // These range types cannot be read and we skip them.
    case EfiReservedMemoryType:
    case EfiUnusableMemory:
    case EfiMemoryMappedIO:
    case EfiMemoryMappedIOPortSpace:
        pmem_debug("EFI range at 0x%llx is non-readable; skipping.",
                   range->start);
        return KERN_SUCCESS;

    // Other ranges are readable and we mark them as such in the bitmap.
    default:
        bits_set = pmem_bitmap_set(bitmap,
                                   range->start / PAGE_SIZE,
                                   range->length / PAGE_SIZE);
        if (bits_set != range->length / PAGE_SIZE) {
            pmem_error("Failed to set bit %llu + %llu",
                       range->start / PAGE_SIZE,
                       range->length / PAGE_SIZE);
            return KERN_FAILURE;
        }
    }

    pmem_debug("Added EFI range at 0x%llx.", range->start);
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

    // This will give the bitmap one bit per every 4K physical page. It can
    // grow if it turns out this number is wrong.
    uint64_t physical_page_count = meta->phys_mem_size / PAGE_SIZE;
    if (physical_page_count > UINT32_MAX) {
        return KERN_FAILURE;
    }
    safety_bitmap = pmem_bitmap_make((uint32_t) physical_page_count);

    if (error != KERN_SUCCESS) {
        pmem_error("Failed to allocate EFI safety bitmap.");
        goto bail;
    }

    // Iterate over the records in the meta struct and build up our bitmap.
    void *current_record = meta->records;

    pmem_debug("Discovered %u memory ranges.", meta->record_count);
    for (unsigned record_idx = 0;
         record_idx < meta->record_count;
         ++record_idx) {
        pmem_meta_record_t *record = current_record;
        if (record->type == pmem_efi_range_type) {
            error = pmem_register_efi_range(&record->efi_range, safety_bitmap);
            if (error != KERN_SUCCESS) {
                goto bail;
            }
        }

        current_record += record->size;
    }

    pmem_info("Initialized EFI range bitmap of size %u with max bit %llu.",
              safety_bitmap->size_bytes, safety_bitmap->highest_bit);

    error = KERN_SUCCESS;

bail:
    if (meta) {
        pmem_metafree(meta);
    }

    return error;
}

void pmem_safety_cleanup(void) {
    if (safety_bitmap) {
        pmem_bitmap_destroy(safety_bitmap);
        safety_bitmap = 0;
    }
}
