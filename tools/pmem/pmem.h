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

#define PMEM_VERSION "2.1.post4";

#include <vector>
#include <aff4/libaff4.h>
#include <aff4/aff4_imager_utils.h>

namespace aff4 {

class PmemImager: public BasicImager {
 protected:
  // A list of files to be removed when we exit.
    std::vector<URN> to_be_removed;
    std::vector<std::string> pagefiles;

    virtual std::string GetName() {
        return "The Pmem physical memory imager. Copyright 2014 Google Inc.";
    }

    virtual std::string GetVersion() {
        return PMEM_VERSION;
    }

    virtual AFF4Status handle_pagefiles();
    virtual AFF4Status handle_compression();

    /**
     * Actually create the image of physical memory.
     *
     *
     * @return STATUS_OK if successful.
     */
    virtual AFF4Status ImagePhysicalMemory() = 0;

    virtual AFF4Status ParseArgs();
    virtual AFF4Status ProcessArgs();

    // Override this to produce a suitable map object for imaging.
    virtual AFF4Status CreateMap_(AFF4Map *map, aff4_off_t *length) = 0;

    virtual AFF4Status WriteMapObject_(
        const URN &map_urn, const URN &output_urn);

    virtual AFF4Status WriteRawFormat_(
        const URN &stream_urn, const URN &output_urn);

    virtual AFF4Status WriteElfFormat_(
        const URN &stream_urn, const URN &output_urn);

    virtual AFF4ScopedPtr<AFF4Stream> GetWritableStream_(
        const URN &output_urn, const URN &volume_urn);

 public:
 PmemImager(): BasicImager() {}
    virtual ~PmemImager();
    virtual AFF4Status Initialize();

    virtual AFF4Status RegisterArgs() {
        AddArg(new TCLAP::ValueArg<std::string>(
                   "", "format", "Specify the output format of memory streams:\n"
                   "  map: An AFF4Map object (Supports compression and sparse).\n"
                   "  elf: An ELF stream. (Supports sparse image).\n"
                   "  raw: A raw padded stream. (Padded with no compression).\n"
                   "If this option is used together with the --export option it "
                   "specifies the output format of the exported stream.",
                   false, "map", "map, elf, raw"));

        AddArg(new TCLAP::SwitchArg(
                   "m", "acquire-memory", "Normally pmem will only acquire memory if "
                   "the user has not asked for something else (like acquiring files, "
                   "exporting etc). This option forces memory to be acquired. It is only "
                   "required when the program is invoked with the --input, --export or "
                   "other actionable flags.\n", false));

        AddArg(new TCLAP::MultiArgToNextFlag<std::string>(
                   "p", "pagefile", "Also capture the pagefile. Note that you must "
                   "provide this option rather than e.g. '--input c:\\pagefile.sys' "
                   "because we can not normally read the pagefile directly. This "
                   "option will use the sleuthkit to read the pagefile.",
                   false, "/path/to/pagefile"));

        return BasicImager::RegisterArgs();
    }
};

#define RETURN_IF_ERROR(expr) do {              \
        AFF4Status status = {expr};             \
        if (status != STATUS_OK) return status; \
    } while (0)

} // namespace aff4

#endif  // TOOLS_PMEM_PMEM_H_
