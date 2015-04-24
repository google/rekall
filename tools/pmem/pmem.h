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

#ifndef TOOLS_PMEM_PMEM_H_
#define TOOLS_PMEM_PMEM_H_

#define PMEM_VERSION "2.0.1";

#include <aff4/libaff4.h>
#include <aff4/aff4_imager_utils.h>


class PmemImager: public BasicImager {
 protected:
  // A list of files to be removed when we exit.
  vector<URN> to_be_removed;
  vector<string> pagefiles;

  virtual string GetName() {
    return "The Pmem physical memory imager. Copyright 2014 Google Inc.";
  }

  virtual string GetVersion() {
    return PMEM_VERSION;
  }

  virtual AFF4Status handle_pagefiles();

  /**
   * Actually create the image of physical memory.
   *
   *
   * @return STATUS_OK if successful.
   */
  virtual AFF4Status ImagePhysicalMemory() = 0;

  virtual AFF4Status ImagePhysicalMemoryToElf();

  virtual AFF4Status ParseArgs();
  virtual AFF4Status ProcessArgs();

 public:
  PmemImager(): BasicImager() {}
  virtual ~PmemImager();
  virtual AFF4Status Initialize();

  virtual AFF4Status RegisterArgs() {
    AddArg(new TCLAP::SwitchArg(
        "", "elf", "Normally pmem will produce an AFF4 volume but this "
        "option will force an ELF Core image file to be produced during "
        "acquisition. Note that this option is not compatible with the "
        "--input or --pagefile options because we can not write multiple "
        "streams into an ELF file.\n"
        "This option is mostly useful for compatibility with legacy memory "
        "analysis tools which do not understand AFF4 images.\n"

        "If this option is used together with the --export option we will "
        "export an ELF file from a stream within the AFF4 image.", false));

    AddArg(new TCLAP::SwitchArg(
        "m", "acquire-memory", "Normally pmem will only acquire memory if "
        "the user has not asked for something else (like acquiring files, "
        "exporting etc). This option forces memory to be acquired. It is only "
        "required when the program is invoked with the --input, --export or "
        "other actionable flags.\n", false));

    AddArg(new TCLAP::MultiArgToNextFlag<string>(
        "p", "pagefile", "Also capture the pagefile. Note that you must "
        "provide this option rather than e.g. '--input c:\\pagefile.sys' "
        "because we can not normally read the pagefile directly. This "
        "option will use the sleuthkit to read the pagefile.",
        false, "/path/to/pagefile"));

    return BasicImager::RegisterArgs();
  }
};

#endif  // TOOLS_PMEM_PMEM_H_
