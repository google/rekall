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


// Negative number causes the kernel to pick the device number. However,
// -1 is not really any good for reasons discussed here:
// https://github.com/opensource-apple/xnu/blob/10.10/bsd/kern/bsd_stubs.c#L242
//
// While not explicitly stated anywhere, Apple's practice is to use -24 as
// a safe value to call makedev with.
#define PMEM_MAJOR -24

// Major number of the devices we create.
extern int pmem_majorno;

// If this is set to 0 (default), reading from /dev/pmem will not attempt to
// read physical memory that the EFI physmap tells us is no backed by
// conventional RAM. If pmem is compiled with write support, this will need to
// be set to 1 before writes are permitted to /dev/pmem.
extern int pmem_allow_unsafe_operations;

// How many times are our devices open?
extern int pmem_open_count;

// This is my load tag. There are many like it, but this one is mine.
extern OSKextLoadTag pmem_load_tag;

// Used to keep track of IOKit allocations. Every part of the driver uses the
// same alloc tag.
extern const char * const pmem_tagname;
extern OSMallocTag pmem_alloc_tag;

////////////////////////////////////////////////////////////////////////////////
// MARK: Lock groups to be used by all the modules.
////////////////////////////////////////////////////////////////////////////////

// Read/write locks, where readers don't block other readers, but writers block
// everyone.
extern lck_grp_t *pmem_rwlock_grp;
extern lck_grp_attr_t *pmem_rwlock_grp_attr;

// Basic mutexes for shared resources.
extern lck_grp_t *pmem_mutex_grp;
extern lck_grp_attr_t *pmem_mutex_grp_attr;


////////////////////////////////////////////////////////////////////////////////
// MARK: Start/stop routines for IOKit
////////////////////////////////////////////////////////////////////////////////

kern_return_t com_google_MacPmem_start(kmod_info_t * ki, void *d);
kern_return_t com_google_MacPmem_stop(kmod_info_t *ki, void *d);

#endif
