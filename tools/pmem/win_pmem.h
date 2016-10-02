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
#ifndef TOOLS_PMEM_WIN_PMEM_H_
#define TOOLS_PMEM_WIN_PMEM_H_

#define PMEM_DEVICE_NAME "pmem"
#define PMEM_SERVICE_NAME "pmem"

// ioctl to get memory ranges from our driver.
#define PMEM_CTRL_IOCTRL CTL_CODE(0x22, 0x101, 0, 3)
#define PMEM_WRITE_ENABLE CTL_CODE(0x22, 0x102, 0, 3)
#define PMEM_INFO_IOCTRL CTL_CODE(0x22, 0x103, 0, 3)

// Available modes
#define PMEM_MODE_IOSPACE 0
#define PMEM_MODE_PHYSICAL 1
#define PMEM_MODE_PTE 2
#define PMEM_MODE_PTE_PCI 3

#define PMEM_MODE_AUTO 99


#include "pmem.h"
#include <stdint.h>


struct PHYSICAL_MEMORY_RANGE {
  uint64_t start;
  uint64_t length;
}__attribute__((packed));

struct PmemMemoryInfo {
  uint64_t CR3;
  uint64_t NtBuildNumber;  // Version of this kernel.
  uint64_t KernBase;  // The base of the kernel image.
  uint64_t KDBG;  // The address of KDBG

  // Support up to 32 processors for KPCR.
  uint64_t KPCR[32];

  uint64_t PfnDataBase;
  uint64_t PsLoadedModuleList;
  uint64_t PsActiveProcessHead;

  // The address of the NtBuildNumber integer - this is used to find the kernel
  // base quickly.
  uint64_t NtBuildNumberAddr;

  // As the driver is extended we can add fields here maintaining
  // driver alignment..
  uint64_t Padding[0xfe];

  uint64_t NumberOfRuns;

  // A Null terminated array of ranges.
  PHYSICAL_MEMORY_RANGE Runs[100];
}__attribute__((packed));


class WinPmemImager: public PmemImager {
 private:
  bool driver_installed_ = false;

 protected:
  /// The URN of the AFF4 volume stored in the imager itself.
  URN imager_urn;
  URN device_urn;                       /**< The URN of the pmem device. */

  string service_name = PMEM_SERVICE_NAME;
  string device_name = PMEM_DEVICE_NAME;
  uint32_t acquisition_mode = PMEM_MODE_AUTO;

  /**
   * This resolver is used to parse the AFF4 volume we bring with us. Our
   * private volume contains all the drivers and tools we need to run on the
   * target. We keep it separate from the resolver we use to create and process
   * other images.
   */
  MemoryDataStore private_resolver;

  virtual AFF4Status CreateMap_(AFF4Map *map, aff4_off_t *length);

  virtual string GetName() {
    return "The WinPmem memory imager.  Copyright 2014 Google Inc.";
  }

  /**
   * Copy the page files to the image. In this implementation we shell out to
   * the sleuthkit's fcat.exe.
   *
   * @return STATUS_OK if successful.
   */
  virtual AFF4Status ImagePageFile();

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
   * Extract a file from the imager's AFF4 volume somewhere in the filesystem.
   *
   * @param input A URN to read.
   * @param output A URN to write.
   *
   * @return
   */
  AFF4Status ExtractFile_(URN input, URN output);

  /**
   * Unloads the driver.
   *
   *
   * @return
   */
  AFF4Status UninstallDriver();

  virtual AFF4Status Initialize();

  virtual AFF4Status RegisterArgs() {
    AddArg(new TCLAP::SwitchArg(
        "l", "load-driver", "Load the driver and exit", false));

    AddArg(new TCLAP::SwitchArg(
        "u", "unload-driver", "Unload the driver and exit", false));

    AddArg(new TCLAP::SwitchArg(
        "", "write-mode", "Enable write mode. You must have the "
        "driver compiled with write support and be on a system with "
        "test signing enabled.", false));

    AddArg(new TCLAP::ValueArg<string>(
        "", "mode", "Select the acquisition mode. Default is PTERemapping.",
        false, "", "MmMapIoSpace, PhysicalMemory, PTERemapping"));

    AddArg(new TCLAP::ValueArg<string>(
        "", "driver", "Use this driver instead of the included one. "
        "This option is rarely used.",
        false, "", "Path to driver."));

    return PmemImager::RegisterArgs();
  }

  virtual AFF4Status handle_pagefiles();
  virtual AFF4Status handle_acquisition_mode();
  virtual AFF4Status ParseArgs();
  virtual AFF4Status ProcessArgs();

  AFF4Status GetMemoryInfo(PmemMemoryInfo *info);

  AFF4Status SetAcquisitionMode();

 public:
  virtual ~WinPmemImager();
};

#endif  // TOOLS_PMEM_WIN_PMEM_H_
