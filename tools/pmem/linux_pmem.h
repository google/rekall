/*
Copyright 2014 Google Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License.  You may obtain a copy of the
License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied.  See the License for the
specific language governing permissions and limitations under the License.
*/

#ifndef _LINUX_PMEM_H
#define _LINUX_PMEM_H

#include "pmem.h"
#include <stdint.h>

struct KCoreRange {
  uint64_t kcore_offset;
  uint64_t phys_offset;
  uint64_t file_offset;
  uint64_t length;
};


class LinuxPmemImager: public PmemImager {
 protected:
  virtual string GetName() {
    return "The LinuxPmem memory imager.  Copyright 2014 Google Inc.";
  }

  /**
   * Parse memory ranges from the /proc/kcore device.
   *
   * @param ranges: This vector will be filled with memory ranges.
   *
   * @return STATUS_OK if some ranges were found.
   */
  AFF4Status ParseKcore(vector<KCoreRange> &ranges);

  /**
   * Actually create the image of physical memory.
   *
   *
   * @return STATUS_OK if successful.
   */
  virtual AFF4Status ImagePhysicalMemory();

  /**
   * First obtain the /proc/kcore memory map and then image it into the output
   * volume.
   *
   * @param ranges: This vector will be filled with memory ranges.
   *
   * @return STATUS_OK if successful.
   */
  AFF4Status ImageKcoreToMap(vector<KCoreRange> &ranges);

  virtual AFF4Status ImagePhysicalMemoryToElf();
};

#endif
