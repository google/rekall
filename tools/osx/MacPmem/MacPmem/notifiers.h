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
//

#ifndef __MacPmem__notifiers__
#define __MacPmem__notifiers__

////////////////////////////////////////////////////////////////////////////////
// Sleep/wake cycle notifiers, used for automatic unloading. Disabled.
////////////////////////////////////////////////////////////////////////////////

#include "MacPmem.h"
#include <IOKit/IOLib.h>
#include <libkern/OSTypes.h>

#ifdef __cplusplus
extern "C" {
#endif

kern_return_t pmem_sleep_init();
kern_return_t pmem_sleep_cleanup();

#ifdef __cplusplus
}
#endif

#endif /* defined(__MacPmem__notifiers__) */
