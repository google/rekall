//  MacPmem - Rekall Memory Forensics
//  Copyright (c) 2016 Google Inc. All rights reserved.
//
//  Implements the /dev/pmem device to provide read/write access to
//  physical memory.
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

#ifndef __MacPmem__msr_h
#define __MacPmem__msr_h

#include <mach/mach_types.h>
#include "util.h"

#ifdef __cplusplus
extern "C" {
#endif

struct pmem_fast_syscall_info {
    int sysenter_supported; // 1 if SEP is supported.

    // If sysenter_supported == 1 then these are set to the corresponding
    // dumped MSRs.
    uint64_t sysenter_eip;
    uint64_t sysenter_esp;
    uint64_t sysenter_cs;
};

// Use cpuid to confirm that SEP (SYSENTER/SYSRET and related MSRs) is enabled.
//
// Returns:
//   struct pmem_fast_syscall_info filled as described above.
struct pmem_fast_syscall_info pmem_get_fast_syscall_info();


// Convenience helper that makes a CPUID request 0 (get vendor string) and
// rebuilds a string out of the registers.
//
// Caller must ensure 'target_buffer' is at least 12 bytes large. The vendor
// string is not null-terminated.
//
// Returns KERN_SUCCESS if it wrote to 'target_buffer'.
kern_return_t pmem_get_cpu_vendorstring(char *target_buffer);

#ifdef __cplusplus
}
#endif

#endif /* meta_msr_h */
