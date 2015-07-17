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

#include "i386_ptable_log.h"

#ifdef PMEM_PTE_DEBUG

const char * const CR3_fmt = "/* %s */: union CR3 {\n" \
                             "    uint64_t value = 0x%llx\n" \
                             "    struct {\n" \
                             "        uint64_t ignored_1 = 0x%llx\n" \
                             "        uint64_t write_through = 0x%llx\n" \
                             "        uint64_t cache_disable = 0x%llx\n" \
                             "        uint64_t ignored_2 = 0x%llx\n" \
                             "        uint64_t pml4_p = 0x%llx\n" \
                             "        uint64_t reserved = 0x%llx\n" \
                             "    };\n" \
                             "}";

void pmem_log_CR3(CR3 x, PmemLogLevel lvl, const char *reason) {
    pmem_log(lvl, CR3_fmt, reason, x.value, x.ignored_1, x.write_through,
             x.cache_disable, x.ignored_2, x.pml4_p, x.reserved);
}


const char * const CR4_fmt = "/* %s */: union CR4 {\n" \
                             "    uint64_t value = 0x%llx\n" \
                             "    struct {\n" \
                             "        uint64_t vme = 0x%llx\n" \
                             "        uint64_t pvi = 0x%llx\n" \
                             "        uint64_t tsd = 0x%llx\n" \
                             "        uint64_t de = 0x%llx\n" \
                             "        uint64_t pse = 0x%llx\n" \
                             "        uint64_t pae = 0x%llx\n" \
                             "        uint64_t mce = 0x%llx\n" \
                             "        uint64_t pge = 0x%llx\n" \
                             "        uint64_t pce = 0x%llx\n" \
                             "        uint64_t osfxsr = 0x%llx\n" \
                             "        uint64_t osxmmexcpt = 0x%llx\n" \
                             "        uint64_t vmxe = 0x%llx\n" \
                             "        uint64_t smxe = 0x%llx\n" \
                             "        uint64_t pcide = 0x%llx\n" \
                             "        uint64_t osxsave = 0x%llx\n" \
                             "        uint64_t smep = 0x%llx\n" \
                             "        uint64_t smap = 0x%llx\n" \
                             "        uint64_t reserved = 0x%llx\n" \
                             "    };\n" \
                             "}";

void pmem_log_CR4(CR4 x, PmemLogLevel lvl, const char *reason) {
    pmem_log(lvl, CR4_fmt, reason, x.value, x.vme, x.pvi, x.tsd, x.de, x.pse,
             x.pae, x.mce, x.pge, x.pce, x.osfxsr, x.osxmmexcpt, x.vmxe,
             x.smxe, x.pcide, x.osxsave, x.smep, x.smap, x.reserved);
}


const char * const VIRT_ADDR_fmt = "/* %s */: union VIRT_ADDR {\n" \
                                   "    uint64_t value = 0x%llx\n" \
                                   "    struct {\n" \
                                   "        uint64_t offset = 0x%llx\n" \
                                   "        uint64_t pt_index = 0x%llx\n" \
                                   "        uint64_t pd_index = 0x%llx\n" \
                                   "        uint64_t pdpt_index = 0x%llx\n" \
                                   "        uint64_t pml4_index = 0x%llx\n" \
                                   "        uint64_t reserved = 0x%llx\n" \
                                   "    };\n" \
                                   "}";

void pmem_log_VIRT_ADDR(VIRT_ADDR x, PmemLogLevel lvl, const char *reason) {
    pmem_log(lvl, VIRT_ADDR_fmt, reason, x.value, x.offset, x.pt_index,
             x.pd_index, x.pdpt_index, x.pml4_index, x.reserved);
}


const char * const PML4E_fmt = "/* %s */: union PML4E {\n" \
                               "    uint64_t value = 0x%llx\n" \
                               "    struct {\n" \
                               "        uint64_t present = 0x%llx\n" \
                               "        uint64_t rw = 0x%llx\n" \
                               "        uint64_t user = 0x%llx\n" \
                               "        uint64_t write_through = 0x%llx\n" \
                               "        uint64_t cache_disable = 0x%llx\n" \
                               "        uint64_t accessed = 0x%llx\n" \
                               "        uint64_t ignored_1 = 0x%llx\n" \
                               "        uint64_t reserved_1 = 0x%llx\n" \
                               "        uint64_t ignored_2 = 0x%llx\n" \
                               "        uint64_t pdpt_p = 0x%llx\n" \
                               "        uint64_t ignored_3 = 0x%llx\n" \
                               "        uint64_t xd = 0x%llx\n" \
                               "    };\n" \
                               "}";

void pmem_log_PML4E(PML4E x, PmemLogLevel lvl, const char *reason) {
    pmem_log(lvl, PML4E_fmt, reason, x.value, x.present, x.rw, x.user,
             x.write_through, x.cache_disable, x.accessed, x.ignored_1,
             x.reserved_1, x.ignored_2, x.pdpt_p, x.ignored_3, x.xd);
}


const char * const PDPTE_fmt = "/* %s */: union PDPTE {\n" \
                               "    uint64_t value = 0x%llx\n" \
                               "    struct {\n" \
                               "        uint64_t present = 0x%llx\n" \
                               "        uint64_t rw = 0x%llx\n" \
                               "        uint64_t user = 0x%llx\n" \
                               "        uint64_t write_through = 0x%llx\n" \
                               "        uint64_t cache_disable = 0x%llx\n" \
                               "        uint64_t accessed = 0x%llx\n" \
                               "        uint64_t dirty = 0x%llx\n" \
                               "        uint64_t page_size = 0x%llx\n" \
                               "        uint64_t ignored_2 = 0x%llx\n" \
                               "        uint64_t pd_p = 0x%llx\n" \
                               "        uint64_t ignored_3 = 0x%llx\n" \
                               "        uint64_t xd = 0x%llx\n" \
                               "    };\n" \
                               "}";

void pmem_log_PDPTE(PDPTE x, PmemLogLevel lvl, const char *reason) {
    pmem_log(lvl, PDPTE_fmt, reason, x.value, x.present, x.rw, x.user,
             x.write_through, x.cache_disable, x.accessed, x.dirty,
             x.page_size, x.ignored_2, x.pd_p, x.ignored_3, x.xd);
}


const char * const PDE_fmt = "/* %s */: union PDE {\n" \
                             "    uint64_t value = 0x%llx\n" \
                             "    struct {\n" \
                             "        uint64_t present = 0x%llx\n" \
                             "        uint64_t rw = 0x%llx\n" \
                             "        uint64_t user = 0x%llx\n" \
                             "        uint64_t write_through = 0x%llx\n" \
                             "        uint64_t cache_disable = 0x%llx\n" \
                             "        uint64_t accessed = 0x%llx\n" \
                             "        uint64_t dirty = 0x%llx\n" \
                             "        uint64_t page_size = 0x%llx\n" \
                             "        uint64_t ignored_2 = 0x%llx\n" \
                             "        uint64_t pt_p = 0x%llx\n" \
                             "        uint64_t ignored_3 = 0x%llx\n" \
                             "        uint64_t xd = 0x%llx\n" \
                             "    };\n" \
                             "}";

void pmem_log_PDE(PDE x, PmemLogLevel lvl, const char *reason) {
    pmem_log(lvl, PDE_fmt, reason, x.value, x.present, x.rw, x.user,
             x.write_through, x.cache_disable, x.accessed, x.dirty,
             x.page_size, x.ignored_2, x.pt_p, x.ignored_3, x.xd);
}


const char * const PTE_fmt = "/* %s */: union PTE {\n" \
                             "    uint64_t value = 0x%llx\n" \
                             "    struct {\n" \
                             "        uint64_t present = 0x%llx\n" \
                             "        uint64_t rw = 0x%llx\n" \
                             "        uint64_t user = 0x%llx\n" \
                             "        uint64_t write_through = 0x%llx\n" \
                             "        uint64_t cache_disable = 0x%llx\n" \
                             "        uint64_t accessed = 0x%llx\n" \
                             "        uint64_t dirty = 0x%llx\n" \
                             "        uint64_t pat = 0x%llx\n" \
                             "        uint64_t global = 0x%llx\n" \
                             "        uint64_t ignored_1 = 0x%llx\n" \
                             "        uint64_t page_frame = 0x%llx\n" \
                             "        uint64_t ignored_3 = 0x%llx\n" \
                             "        uint64_t xd = 0x%llx\n" \
                             "    };\n" \
                             "}";

void pmem_log_PTE(PTE x, PmemLogLevel lvl, const char *reason) {

    pmem_log(lvl, PTE_fmt, reason, x.value, x.present, x.rw, x.user,
             x.write_through, x.cache_disable, x.accessed, x.dirty, x.pat,
             x.global, x.ignored_1, x.page_frame, x.ignored_3, x.xd);
}

#endif
