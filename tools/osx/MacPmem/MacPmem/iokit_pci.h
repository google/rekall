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

#ifndef __MacPmem__iokit_pci__
#define __MacPmem__iokit_pci__

#include <libkern/libkern.h>
#include <mach/mach_types.h>
#include <IOKit/pci/IOPCIDevice.h>
#include "util.h"

typedef pmem_signal_t (*pmem_pci_callback_t)(IOPCIDevice *dev,
                                             IODeviceMemory *mem,
                                             unsigned mem_idx,
                                             void *ctx);
kern_return_t pmem_iokit_enumerate_pci(pmem_pci_callback_t callback, void *ctx);

#endif /* defined(__MacPmem__iokit_pci__) */
