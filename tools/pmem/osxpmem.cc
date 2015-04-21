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

#include "osxpmem.h"
#include <sys/sysctl.h>


AFF4Status OSXPmemImager::ImagePhysicalMemory() {
  std::cout << "Imaging memory\n";

  AFF4Status res = InstallDriver();
  if (res != STATUS_OK)
    return res;

  vector<OSXPmemRange> ranges;
  res = GetRanges(ranges);
  if (res != STATUS_OK)
    return res;

  for(auto it: ranges) {
    LOG(ERROR) << "Range " << it.phys_offset << " " << it.length;
  }

  URN output_urn;
  res = GetOutputVolumeURN(output_urn);
  if (res != STATUS_OK)
    return res;

  URN map_urn = output_urn.Append(device_name);
  URN map_data_urn = map_urn.Append("data");

  // Set the user's peferred compression method.
  resolver.Set(map_data_urn, AFF4_IMAGE_COMPRESSION, new URN(
      CompressionMethodToURN(compression)));

  // This is a physical memory image.
  resolver.Set(map_urn, AFF4_CATEGORY, new URN(AFF4_MEMORY_PHYSICAL));

  AFF4ScopedPtr<AFF4Map> map_stream = AFF4Map::NewAFF4Map(
      &resolver, map_urn, output_urn);
  if (!map_stream)
    return IO_ERROR;

  AFF4ScopedPtr<AFF4Stream> device_stream = resolver.AFF4FactoryOpen<AFF4Stream>(
      device_urn);
  if (!device_stream)
    return IO_ERROR;

  for (auto range : ranges) {
    device_stream->Seek(range.phys_offset, SEEK_SET);
    map_stream->Seek(range.phys_offset, SEEK_SET);
    res = device_stream->CopyToStream(
        *map_stream, range.length,
        std::bind(&OSXPmemImager::progress_renderer, this,
                  std::placeholders::_1, std::placeholders::_2));

    if (res != STATUS_OK)
      return res;
  };

  // Also capture these by default.
  if (inputs.size() == 0) {
    LOG(INFO) << "Adding default file collections.";
    // After 10.10 the kernel is here:
    inputs.push_back("/System/Library/Kernels/*");
    inputs.push_back("/mach_kernel");
    inputs.push_back(aff4_sprintf("%s_info", device_name.c_str()));
    inputs.push_back("/System/Library/Extensions/*.kext/Contents/*/*");
  };

  res = process_input();
  return res;
};


AFF4Status OSXPmemImager::Initialize() {
  return STATUS_OK;
};


static bool efi_readable(EFI_MEMORY_TYPE type) {
  return (type == EfiLoaderCode ||
          type == EfiLoaderData ||
          type == EfiBootServicesCode ||
          type == EfiBootServicesData ||
          type == EfiRuntimeServicesCode ||
          type == EfiRuntimeServicesData ||
          type == EfiConventionalMemory ||
          type == EfiACPIReclaimMemory ||
          type == EfiACPIMemoryNVS ||
          type == EfiPalCode);
};


AFF4Status OSXPmemImager::GetRanges(vector<OSXPmemRange> &ranges) {
  // Use a temporary AFF4Map to merge ranges.
  MemoryDataStore resolver;
  AFF4Map temp_map = AFF4Map(&resolver);
  ranges.clear();

  AFF4ScopedPtr<FileBackedObject> device_stream = resolver.AFF4FactoryOpen
    <FileBackedObject>(device_urn);

  if (!device_stream)
    return IO_ERROR;

  int error = -1;
  pmem_meta_t *meta = 0;
  size_t metalen = 0;
  while (1) {
    // Get the required size of the meta struct (it varies).
    sysctlbyname(sysctl_name.c_str(), 0, &metalen, 0, 0);

    // Allocate the required number of bytes.
    meta = (pmem_meta_t *)malloc(metalen);
    error = sysctlbyname(sysctl_name.c_str(), meta, &metalen, 0, 0);
    if (error == 0 && metalen > 0) {
      break;
    }

    free(meta);
    if (errno != ENOMEM) {
      // If the call failed because the buffer was too small, we can
      // retry; bail otherwise.
      LOG(ERROR) << "sysctlbyname() error: " << errno;
      return IO_ERROR;
    }
  }

  pmem_meta_record_t *record;

  // Fetch the Efi ranges.
  record = (pmem_meta_record_t *)((char *)meta +
                                  meta->records_offset);
  for (int i=0; i < meta->record_count; i++) {
    if (record->type == pmem_efi_range_type &&
        efi_readable(record->efi_range.efi_type)) {
      temp_map.AddRange(record->efi_range.start,
                        record->efi_range.start,
                        record->efi_range.length,
                        device_urn);
    };

    // Go to the next record.
    record = (pmem_meta_record_t *)((char *)record + record->size);
  };

  URN null_URN("aff4:/NULL");

  record = (pmem_meta_record_t *)((char *)meta +
                                  meta->records_offset);
  for (int i=0; i < meta->record_count; i++) {
    if (record->type == pmem_pci_range_type &&
        strnstr(record->purpose, "GFX0", PMEM_NAMESIZE)) {
      temp_map.AddRange(record->pci_range.start,
                        record->pci_range.start,
                        record->pci_range.length,
                        null_URN);
    };

    // Go to the next record.
    record = (pmem_meta_record_t *)((char *)record + record->size);
  };

  free(meta);

  for (auto it: temp_map.GetRanges()) {
    if (it.target_id == 0) {
      OSXPmemRange range;

      range.phys_offset = it.map_offset;
      range.length = it.length;

      ranges.push_back(range);
    };
  };

  return STATUS_OK;
};


AFF4Status OSXPmemImager::ParseArgs() {
  AFF4Status result = PmemImager::ParseArgs();

  string device = GetArg<TCLAP::ValueArg<string>>("device")->getValue();

  device_name = aff4_sprintf("/dev/%s", device.c_str());
  sysctl_name = aff4_sprintf("kern.%s_info", device.c_str());
  device_urn = URN::NewURNFromFilename(device_name);

  driver_urn = URN::NewURNFromFilename(
    GetArg<TCLAP::ValueArg<string>>("driver")->getValue());

  return result;
};

AFF4Status OSXPmemImager::ProcessArgs() {
  AFF4Status result = PmemImager::ProcessArgs();

  return result;
};

AFF4Status OSXPmemImager::UninstallDriver() {
  return STATUS_OK;
};


AFF4Status OSXPmemImager::InstallDriver() {
  AFF4ScopedPtr<FileBackedObject> device_stream = resolver.AFF4FactoryOpen
    <FileBackedObject>(device_urn);

  if (!device_stream) {
    LOG(INFO) << "Device " << device_urn.SerializeToString() <<
      " does not yet exist, will try to load driver.";

    // TODO.
  };

  return STATUS_OK;
};


OSXPmemImager::~OSXPmemImager() {
  if (driver_installed_) {
    UninstallDriver();
  };
};
