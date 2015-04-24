/*
Copyright 2015 Google Inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License.  You may obtain a copy of the
License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied.  See the License for the
specific language governing permissions and limitations under the License.
*/

#ifndef TOOLS_PMEM_OSXPMEM_H_
#define TOOLS_PMEM_OSXPMEM_H_

#include "pmem.h"
// Driver API.
#include "MacPmem/pmem_common.h"
#include <stdint.h>

struct OSXPmemRange {
  uint64_t phys_offset;
  uint64_t length;
};


class OSXPmemImager: public PmemImager {
 private:
  bool driver_installed_ = false;
  URN device_urn;                       /**< The URN of the pmem device. */
  URN driver_urn;
  string sysctl_name;
  string device_name;

 protected:
  virtual string GetName() {
    return "The OSXPmem memory imager.  Copyright 2015 Google Inc.";
  }

  /**
   * Actually create the image of physical memory.
   *
   *
   * @return STATUS_OK if successful.
   */
  virtual AFF4Status ImagePhysicalMemory();

  /**
   * Attemptes to unpack and install the driver.
   *
   *
   * @return STATUS_OK if the driver was correctly installed.
   */
  AFF4Status InstallDriver();

  /**
   * Unloads the driver.
   *
   *
   * @return
   */
  AFF4Status UninstallDriver();

  AFF4Status GetRanges(vector<OSXPmemRange> &ranges);

  virtual AFF4Status Initialize();

  virtual AFF4Status RegisterArgs() {
    AddArg(new TCLAP::ValueArg<string>(
        "", "driver", "Path to driver to load. "
        "This is usually set to the driver included in the package.",
        false, "MacPmem.kext", "Path to driver."));

    AddArg(new TCLAP::ValueArg<string>(
        "", "device", "Path to device to image. "
        "Note the device name depends on the specific driver.",
        false, "pmem", "Path to device."));

    return PmemImager::RegisterArgs();
  }

  virtual AFF4Status ParseArgs();
  virtual AFF4Status ProcessArgs();

 public:
  virtual ~OSXPmemImager();
  virtual AFF4Status ImagePhysicalMemoryToElf();
};

#endif  // TOOLS_PMEM_OSXPMEM_H_
