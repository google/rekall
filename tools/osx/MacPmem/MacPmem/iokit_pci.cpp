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

#include "iokit_pci.h"
#include "logging.h"


kern_return_t pmem_iokit_enumerate_pci(pmem_pci_callback_t callback,
                                       void *ctx) {
    kern_return_t error = KERN_FAILURE;
    OSObject *obj = nullptr;
    OSDictionary *search = nullptr;
    OSIterator *iter = nullptr;
    IOPCIDevice *dev = nullptr;
    IODeviceMemory *mem = nullptr;
    IOItemCount mem_count = 0;
    int cmp;

    search = IOService::serviceMatching("IOPCIDevice");
    iter = IOService::getMatchingServices(search);
    if (!iter) {
        pmem_error("Couldn't find any PCI devices.");
        goto bail;
    }

    while ((obj = iter->getNextObject())) {
        cmp = strncmp("IOPCIDevice",
                      obj->getMetaClass()->getClassName(),
                      strlen("IOPCIDevice"));
        if (cmp != 0) {
            // I haven't seen the above return anything other than
            // PCI devices, but Apple's documentation is sparse (which
            // is a nice word for what it is) and doesn't actually
            // say anything about what's guaranteed to be returned.
            // I'd just as well rather not chance it.
            pmem_warn("Expected IOPCIDevice but got %s - skipping.",
                      obj->getMetaClass()->getClassName());
            continue;
        }
        dev = (IOPCIDevice *)obj;
        mem_count = dev->getDeviceMemoryCount();
        pmem_debug("Found PCI device %s", dev->getName());

        for (unsigned idx = 0; idx < mem_count; ++idx) {
            pmem_debug("Memory segment %d found.", idx);
            mem = dev->getDeviceMemoryWithIndex(idx);
            pmem_signal_t signal = callback(dev, mem, idx, ctx);
            if (signal == pmem_Stop) {
                error = KERN_FAILURE;
                goto bail;
            }
        }
    }

    error = KERN_SUCCESS;

bail:
    if (iter) {
        iter->release();
    }

    if (search) {
        search->release();
    }

    return error;
}
