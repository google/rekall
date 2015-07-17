//  MacPmem - Rekall Memory Forensics
//  Copyright (c) 2015 Google Inc. All rights reserved.
//
//  Implements the /dev/pmem device to provide read/write access to
//  physical memory.
//
//  Authors:
//   Johannes Stüttgen
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

#ifndef MacPmem_i386_ptable_h
#define MacPmem_i386_ptable_h

#include <sys/types.h>

// Page frame to page, and page to page frame.
#define PFN_TO_PAGE(pfn) (pfn << PAGE_SHIFT)
#define PAGE_TO_PFN(pfn) (pfn >> PAGE_SHIFT)


////////////////////////////////////////////////////////////////////////////////
// Bitwise structs to reading x86/64 paging structures without macros.
////////////////////////////////////////////////////////////////////////////////

#pragma pack(push, 1)
typedef union CR3_ {
    uint64_t value;
    struct {
        uint64_t ignored_1     : 3;
        uint64_t write_through : 1;
        uint64_t cache_disable : 1;
        uint64_t ignored_2     : 7;
        uint64_t pml4_p        : 40;
        uint64_t reserved      : 12;
    };
} CR3;


typedef union CR4_ {
    uint64_t value;
    struct {
        uint64_t vme           : 1;
        uint64_t pvi           : 1;
        uint64_t tsd           : 1;
        uint64_t de            : 1;
        uint64_t pse           : 1;
        uint64_t pae           : 1;
        uint64_t mce           : 1;
        uint64_t pge           : 1;
        uint64_t pce           : 1;
        uint64_t osfxsr        : 1;
        uint64_t osxmmexcpt    : 1;
        uint64_t vmxe          : 1;
        uint64_t smxe          : 1;
        uint64_t pcide         : 1;
        uint64_t osxsave       : 1;
        uint64_t smep          : 1;
        uint64_t smap          : 1;
        uint64_t reserved      : 47;
    };
} CR4;


typedef union VIRT_ADDR_ {
    uint64_t value;
    void *pointer;
    struct {
        uint64_t offset        : 12;
        uint64_t pt_index      :  9;
        uint64_t pd_index      :  9;
        uint64_t pdpt_index    :  9;
        uint64_t pml4_index    :  9;
        uint64_t reserved      : 16;
    };
} VIRT_ADDR;


typedef uint64_t PHYS_ADDR;


typedef union PML4E_ {
    uint64_t value;
    struct {
        uint64_t present        : 1;
        uint64_t rw             : 1;
        uint64_t user           : 1;
        uint64_t write_through  : 1;
        uint64_t cache_disable  : 1;
        uint64_t accessed       : 1;
        uint64_t ignored_1      : 1;
        uint64_t reserved_1     : 1;
        uint64_t ignored_2      : 4;
        uint64_t pdpt_p         : 40;
        uint64_t ignored_3      : 11;
        uint64_t xd             : 1;
    };
} PML4E;


typedef union PDPTE_ {
    uint64_t value;
    struct {
        uint64_t present        : 1;
        uint64_t rw             : 1;
        uint64_t user           : 1;
        uint64_t write_through  : 1;
        uint64_t cache_disable  : 1;
        uint64_t accessed       : 1;
        uint64_t dirty          : 1;
        uint64_t page_size      : 1;
        uint64_t ignored_2      : 4;
        uint64_t pd_p           : 40;
        uint64_t ignored_3      : 11;
        uint64_t xd             : 1;
    };
} PDPTE;


typedef union PDE_ {
    uint64_t value;
    struct {
        uint64_t present        : 1;
        uint64_t rw             : 1;
        uint64_t user           : 1;
        uint64_t write_through  : 1;
        uint64_t cache_disable  : 1;
        uint64_t accessed       : 1;
        uint64_t dirty          : 1;
        uint64_t page_size      : 1;
        uint64_t ignored_2      : 4;
        uint64_t pt_p           : 40;
        uint64_t ignored_3      : 11;
        uint64_t xd             : 1;
    };
} PDE;


typedef union PTE_ {
    uint64_t value;
    VIRT_ADDR vaddr;
    struct {
        uint64_t present        : 1;
        uint64_t rw             : 1;
        uint64_t user           : 1;
        uint64_t write_through  : 1;
        uint64_t cache_disable  : 1;
        uint64_t accessed       : 1;
        uint64_t dirty          : 1;
        uint64_t pat            : 1;
        uint64_t global         : 1;
        uint64_t ignored_1      : 3;
        uint64_t page_frame     : 40;
        uint64_t ignored_3      : 11;
        uint64_t xd             : 1;
    };
} PTE;
#pragma pack(pop)

#endif
