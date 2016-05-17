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
#include <stdlib.h>
#include <libgen.h>
#include <sys/sysctl.h>
#include <mach-o/dyld.h>

AFF4Status OSXPmemImager::ImagePhysicalMemory() {
  std::cout << "Imaging memory\n";

  AFF4Status res;

  res = InstallDriver();
  if (res != STATUS_OK)
    return res;

  URN output_urn;
  res = GetOutputVolumeURN(output_volume_urn);
  if (res != STATUS_OK)
    return res;

  // We image memory into this map stream.
  URN map_urn = output_volume_urn.Append(device_name);

  AFF4ScopedPtr<AFF4Volume> volume = resolver.AFF4FactoryOpen<AFF4Volume>(
      output_volume_urn);

  // This is a physical memory image.
  resolver.Set(map_urn, AFF4_CATEGORY, new URN(AFF4_MEMORY_PHYSICAL));

  string format = GetArg<TCLAP::ValueArg<string>>("format")->getValue();

  if (format == "map") {
    res = WriteMapObject_(map_urn, output_volume_urn);
  } else if (format == "raw") {
    res = WriteRawFormat_(map_urn, output_volume_urn);
  } else if (format == "elf") {
    res = WriteElfFormat_(map_urn, output_volume_urn);
  }

  if (res != STATUS_OK) {
    return res;
  }

  actions_run.insert("memory");

  // Also capture these files by default.
  if (inputs.size() == 0) {
    LOG(INFO) << "Adding default file collections.";
    inputs.push_back("/boot/*");
  }

  return res;
}

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
}

AFF4Status OSXPmemImager::CreateMap_(AFF4Map *map, aff4_off_t *length) {
  AFF4ScopedPtr<FileBackedObject> device_stream = resolver.AFF4FactoryOpen
    <FileBackedObject>(device_urn);

  if (!device_stream) {
    LOG(ERROR) << "Unable to open " << device_name.c_str() <<
        " - Are you root?";
    return IO_ERROR;
  }

  int error = -1;
  pmem_meta_t *meta = 0;
  size_t metalen = 0;
  while (1) {
    // Get the required size of the meta struct (it varies).
    sysctlbyname(sysctl_name.c_str(), 0, &metalen, 0, 0);

    // Allocate the required number of bytes.
    meta = reinterpret_cast<pmem_meta_t *>(malloc(metalen));
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

  if (meta->pmem_api_version != MINIMUM_PMEM_API_VERSION) {
    LOG(ERROR) << "Pmem driver version incompatible. Reported " <<
        meta->pmem_api_version << " required: " <<
        static_cast<int>(MINIMUM_PMEM_API_VERSION) << "\n";
    return IO_ERROR;
  }

  // Fetch the Efi ranges.
  record = reinterpret_cast<pmem_meta_record_t *>(
      reinterpret_cast<char *>(meta) + meta->records_offset);
  for (int i=0; i < meta->record_count; i++) {
    if (record->type == pmem_efi_range_type &&
        efi_readable(record->efi_range.efi_type)) {
      map->AddRange(record->efi_range.start,
                    record->efi_range.start,
                    record->efi_range.length,
                    device_urn);
      *length += record->efi_range.length;
    }

    // Go to the next record.
    record = reinterpret_cast<pmem_meta_record_t *>(
        reinterpret_cast<char *>(record) + record->size);
  }

  free(meta);

  if (map->Size() == 0) {
    LOG(INFO) << "No ranges found.";
    return NOT_FOUND;
  }

  return STATUS_OK;
}


AFF4Status OSXPmemImager::ParseArgs() {
  AFF4Status result = PmemImager::ParseArgs();

  string device = GetArg<TCLAP::ValueArg<string>>("device")->getValue();

  device_name = aff4_sprintf("/dev/%s", device.c_str());
  sysctl_name = aff4_sprintf("kern.%s_info", device.c_str());
  device_urn = URN::NewURNFromFilename(device_name);

  driver_urn = URN::NewURNFromFilename(
    GetArg<TCLAP::ValueArg<string>>("driver")->getValue());

  return result;
}

AFF4Status OSXPmemImager::ProcessArgs() {
  AFF4Status result = PmemImager::ProcessArgs();

  return result;
}

AFF4Status OSXPmemImager::UninstallDriver() {
  std::cout << "Uninstalling driver" << driver_path << "\n";
  string argv = aff4_sprintf("/sbin/kextunload %s", driver_path.c_str());
  if (system(argv.c_str()) != 0) {
    LOG(ERROR) << "Unable to unload driver at " << driver_path.c_str();
    return IO_ERROR;
  }
  driver_installed_ = false;

  return STATUS_OK;
}


AFF4Status OSXPmemImager::InstallDriver() {
  AFF4ScopedPtr<FileBackedObject> device_stream = resolver.AFF4FactoryOpen
    <FileBackedObject>(device_urn);

  if (!device_stream) {
    // Device does not exist, try to load it ourselves.
    char path[1024 * 4];
    uint32_t size = sizeof(path);
    if (_NSGetExecutablePath(path, &size) != 0) {
      LOG(ERROR) << "Executable path too long.";
      return IO_ERROR;
    }

    driver_path = aff4_sprintf("%s/MacPmem.kext", dirname(path));
    string argv = aff4_sprintf("/sbin/kextload %s", driver_path.c_str());
    if (system(argv.c_str()) != 0) {
      LOG(ERROR) << "Unable to load driver at " << driver_path.c_str();
      return IO_ERROR;
    }
    std::cout << "Installed driver from " << driver_path << "\n";
    driver_installed_ = true;
  }

  return STATUS_OK;
}


OSXPmemImager::~OSXPmemImager() {
  if (driver_installed_) {
    UninstallDriver();
  }
}
