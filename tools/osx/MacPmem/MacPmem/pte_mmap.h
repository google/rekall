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

#ifdef __cplusplus
extern "C" {
#endif

    extern vm_address_t pmem_rogue_page;
    extern vm_size_t pmem_rogue_page_size;

    kern_return_t pmem_pte_init(void);
    void pmem_pte_cleanup(void);

    // Map the rogue page to this physical address.
    kern_return_t pmem_pte_map_rogue(addr64_t paddr);
    kern_return_t pmem_read_rogue(struct uio *uio);



#ifdef __cplusplus
}
#endif

#endif /* defined(__MacPmem__pte_mmap__) */
