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

#ifndef TOOLS_PMEM_LINUX_PMEM_H_
#define TOOLS_PMEM_LINUX_PMEM_H_

#include "pmem.h"
#include <stdint.h>

namespace aff4 {

class LinuxPmemImager: public PmemImager {
 protected:
    virtual std::string GetName() {
        return "The LinuxPmem memory imager.  Copyright 2014 Google Inc.";
  }

  /**
   * Actually create the image of physical memory.
   *
   *
   * @return STATUS_OK if successful.
   */
  virtual AFF4Status ImagePhysicalMemory();
 private:
  AFF4Status CreateMap_(AFF4Map *map, aff4_off_t *length);
  AFF4Status ParseIOMap_(std::vector<aff4_off_t> *ram);
};

} // namespace aff4

#endif  // TOOLS_PMEM_LINUX_PMEM_H_
