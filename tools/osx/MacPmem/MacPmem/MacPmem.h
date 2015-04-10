//  MacPmem - Rekall Memory Forensics
//  Copyright (c) 2015 Google Inc. All rights reserved.
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

// This file starts and stops the extension and manages the lifecycle of both
// character devices created by the extension.

#ifndef MacPmem_MacPmem_h
#define MacPmem_MacPmem_h

#include <libkern/OSMalloc.h>
#include <mach/mach_types.h>
#include <sys/uio.h>
#include <libkern/locks.h>
#include <libkern/OSKextLib.h>


#ifdef __LP64__
#define PMEM_KERNEL_VOFFSET ((uint64_t) 0xFFFFFF8000000000ULL)
#else
#define PMEM_KERNEL_VOFFSET ((uint32_t) 0x00000000UL)
#endif

// Negative number causes the kernel to pick the device number. However,
// -1 is not really any good for reasons discussed here:
// https://github.com/opensource-apple/xnu/blob/10.10/bsd/kern/bsd_stubs.c#L242
//
// While not explicitly stated anywhere, Apple's practice is to use -24 as
// a safe value to call makedev with.
#define PMEM_MAJOR -24
extern int pmem_majorno;

extern int pmem_open_count;
extern OSKextLoadTag pmem_load_tag;

extern const char * const pmem_tagname;
extern OSMallocTag pmem_tag;

// Lock groups to be used by all the modules.
extern lck_grp_t *pmem_rwlock_grp;
extern lck_grp_attr_t *pmem_rwlock_grp_attr;
extern lck_grp_t *pmem_mutex_grp;
extern lck_grp_attr_t *pmem_mutex_grp_attr;


kern_return_t com_google_MacPmem_start(kmod_info_t * ki, void *d);
kern_return_t com_google_MacPmem_stop(kmod_info_t *ki, void *d);

#endif
