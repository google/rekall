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

#ifndef __MacPmem__info__
#define __MacPmem__info__

////////////////////////////////////////////////////////////////////////////////
// kern.pmem_info & /dev/pmem_info implementations
////////////////////////////////////////////////////////////////////////////////

#include <libkern/libkern.h>
#include <mach/mach_types.h>
#include <sys/sysctl.h>
#include "pmem_common.h"
#include "util.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef pmem_signal_t (*pmem_memory_callback_t)(pmem_meta_record_t, void *);

kern_return_t pmem_fillmeta(pmem_meta_t **metaret, int flags);

kern_return_t pmem_openmeta();
kern_return_t pmem_readmeta(struct uio *uio);
kern_return_t pmem_closemeta();

void pmem_metafree(pmem_meta_t *meta);
void pmem_meta_cleanup();
kern_return_t pmem_meta_init();

#ifdef __cplusplus
}
#endif

#endif /* defined(__MacPmem__info__) */
