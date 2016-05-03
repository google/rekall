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

#include "cpu.h"

// For register numbers.
#include <i386/proc_reg.h>

// See the Intel reference manual [1] - we only define what we need, because the
// full list would be massive.
// 1: http://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-instruction-set-reference-manual-325383.pdf
#define CPUID_OUT_EDX_SEP (1ULL << 11)
#define CPUID_IN_EAX_GETVENDORSTRING   0
#define CPUID_IN_EAX_GETFEATURES       1

enum pmem_general_registers {
    EAX, EBX, ECX, EDX
};

static inline void pmem_do_cpuid(uint32_t *registers) {
    __asm__ volatile ("cpuid"
                      : "=a" (registers[EAX]), "=b" (registers[EBX]),
                      "=c" (registers[ECX]), "=d" (registers[EDX])
                      : "a" (registers[EAX]), "b" (registers[EBX]),
                      "c" (registers[ECX]), "d" (registers[EDX]));
}

// Verify that fast system calls are supported (SYSENTER/SYSRET).
int pmem_cpuid_sep_supported() {
    uint32_t registers[4];
    registers[EAX] = CPUID_IN_EAX_GETFEATURES;

    pmem_do_cpuid(registers);

    return registers[EDX] & CPUID_OUT_EDX_SEP;
}

struct pmem_fast_syscall_info pmem_get_fast_syscall_info() {
    struct pmem_fast_syscall_info res;
    bzero(&res, sizeof(struct pmem_fast_syscall_info));

    if (pmem_cpuid_sep_supported()) {
        res.sysenter_eip = rdmsr64(MSR_IA32_SYSENTER_EIP);
        res.sysenter_esp = rdmsr64(MSR_IA32_SYSENTER_ESP);
        res.sysenter_cs = rdmsr64(MSR_IA32_SYSENTER_CS);

        res.sysenter_supported = 1;
    }

    return res;
}

kern_return_t pmem_get_cpu_vendorstring(char *target_buffer) {
    uint32_t reg[4];
    reg[EAX] = CPUID_IN_EAX_GETVENDORSTRING;

    pmem_do_cpuid(reg);

    if (reg[EBX] == 0) {
        return KERN_FAILURE;
    }

    // EBX, EDX and ECX contain the vendor string in that order.
    strncpy(target_buffer, (char *)(reg + EBX), 4);
    strncpy(target_buffer + 8, (char *)(reg + ECX), 4);
    strncpy(target_buffer + 4, (char *)(reg + EDX), 4);

    return KERN_SUCCESS;
}
