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
#include "MacPmem/Common/pmem_common.h"
#include <stdint.h>

class OSXPmemImager: public PmemImager {
 private:
  string device_name;
  string sysctl_name;
  URN device_urn;   /**< The URN of the pmem device. */
  URN driver_urn;
  bool driver_installed_ = false;
  
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

  virtual AFF4Status CreateMap_(AFF4Map *map, aff4_off_t *length);  
  virtual AFF4Status ParseArgs();
  virtual AFF4Status ProcessArgs();

 public:
  virtual ~OSXPmemImager();
};

#endif  // TOOLS_PMEM_OSXPMEM_H_
