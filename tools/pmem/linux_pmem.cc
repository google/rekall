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

#include "linux_pmem.h"
#include "elf.h"

AFF4Status LinuxPmemImager::CreateMap_(AFF4Map *map, aff4_off_t *length) {
  LOG(INFO) << "Will parse /proc/kcore";

  *length = 0;
  URN kcore_urn = URN::NewURNFromFilename("/proc/kcore");

  AFF4ScopedPtr<AFF4Stream> stream = resolver.AFF4FactoryOpen<AFF4Stream>(
      kcore_urn);

  if (!stream) {
    LOG(ERROR) << "Unable to open /proc/kcore - Are you root?";
    return IO_ERROR;
  }

  Elf64_Ehdr header;
  if (stream->ReadIntoBuffer(
          reinterpret_cast<char *>(&header),
          sizeof(header)) != sizeof(header)) {
    LOG(ERROR) << "Unable to read /proc/kcore - Are you root?";
    return IO_ERROR;
  }

  // Check the header for sanity.
  if (header.ident[0] != ELFMAG0 ||
      header.ident[1] != ELFMAG1 ||
      header.ident[2] != ELFMAG2 ||
      header.ident[3] != ELFMAG3 ||
      header.ident[4] != ELFCLASS64 ||
      header.ident[5] != ELFDATA2LSB ||
      header.ident[6] != EV_CURRENT ||
      header.type     != ET_CORE ||
      header.machine  != EM_X86_64 ||
      header.version  != EV_CURRENT ||
      header.phentsize != sizeof(Elf64_Phdr)) {
    LOG(ERROR) << "Unable to parse /proc/kcore - Are you root?";
    return INVALID_INPUT;
  }

  // Read the physical headers.
  stream->Seek(header.phoff, SEEK_SET);
  for (int i = 0; i < header.phnum; i++) {
    Elf64_Phdr pheader;
    if (stream->ReadIntoBuffer(
            reinterpret_cast<char *>(&pheader),
            sizeof(pheader)) != sizeof(pheader)) {
      return IO_ERROR;
    }

    if (pheader.type != PT_LOAD)
      continue;

    if (0xffff880000000000ULL <= pheader.vaddr &&
       pheader.vaddr <= 0xffffc7ffffffffffULL) {
      LOG(INFO) << "Found range " << std::hex << pheader.vaddr << " " <<
          std::hex << pheader.memsz << " At offset " << std::hex << pheader.off;
      map->AddRange(pheader.vaddr - 0xffff880000000000ULL,
                    pheader.off,
                    pheader.memsz,
                    kcore_urn);
      *length += pheader.memsz;
    }
  }

  if (map->Size() == 0) {
    LOG(INFO) << "No ranges found in /proc/kcore";
    return NOT_FOUND;
  }

  return STATUS_OK;
}


AFF4Status LinuxPmemImager::ImagePhysicalMemory() {
  std::cout << "Imaging memory\n";

  URN output_urn;
  AFF4Status res = GetOutputVolumeURN(output_volume_urn);
  if (res != STATUS_OK)
    return res;

  // We image memory into this map stream.
  URN map_urn = output_volume_urn.Append("proc/kcore");

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

  res = process_input();
  return res;
}
