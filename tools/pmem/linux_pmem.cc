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
#include <pcre++.h>

namespace aff4 {

// Return the physical offset of all the system ram mappings.
AFF4Status LinuxPmemImager::ParseIOMap_(std::vector<aff4_off_t> *ram) {
    resolver.logger->info("Will parse /proc/iomem");
    ram->clear();

    URN iomap_urn = URN::NewURNFromFilename("/proc/iomem");
    AFF4ScopedPtr<AFF4Stream> stream = resolver.AFF4FactoryOpen<AFF4Stream>(
        iomap_urn);
    if (!stream) {
        resolver.logger->error("Unable to open /proc/iomap");
        return IO_ERROR;
    }

    auto data = stream->Read(0x10000);
    pcrepp::Pcre RAM_regex("(([0-9a-f]+)-([0-9a-f]+) : System RAM)");
    int offset = 0;
    while (RAM_regex.search(data, offset)) {
        uint64_t start = strtoll(RAM_regex.get_match(1).c_str(), nullptr, 16);
        uint64_t end = strtoll(RAM_regex.get_match(2).c_str(), nullptr, 16);
        resolver.logger->info("System RAM {:x} - {:x}", start, end);

        ram->push_back(start);
        offset = RAM_regex.get_match_end(0);
    }

    if (ram->size() == 0) {
        resolver.logger->critical("/proc/iomap has no System RAM.");
        return IO_ERROR;
    }

    return STATUS_OK;
}


AFF4Status LinuxPmemImager::CreateMap_(AFF4Map *map, aff4_off_t *length) {
  std::cout << "Processing /proc/kcore";

  // The start address of each physical memory range.
  std::vector<aff4_off_t> physical_range_start;
  RETURN_IF_ERROR(ParseIOMap_(&physical_range_start));

  *length = 0;
  URN kcore_urn = URN::NewURNFromFilename("/proc/kcore");

  AFF4ScopedPtr<AFF4Stream> stream = resolver.AFF4FactoryOpen<AFF4Stream>(
      kcore_urn);

  if (!stream) {
      resolver.logger->critical("Unable to open /proc/kcore - Are you root?");
      return IO_ERROR;
  }

  Elf64_Ehdr header;
  if (stream->ReadIntoBuffer(
          reinterpret_cast<char *>(&header),
          sizeof(header)) != sizeof(header)) {
      resolver.logger->critical("Unable to read /proc/kcore - Are you root?");
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
      resolver.logger->error("Unable to parse /proc/kcore - Are you root?");
      return INVALID_INPUT;
  }

  // Read the physical headers.
  stream->Seek(header.phoff, SEEK_SET);

  // The index in physical_range_start vector we are currently seeking.
  int physical_range_start_index = 0;

  for (int i = 0; i < header.phnum; i++) {
    Elf64_Phdr pheader;
    if (stream->ReadIntoBuffer(
            reinterpret_cast<char *>(&pheader),
            sizeof(pheader)) != sizeof(pheader)) {
      return IO_ERROR;
    }

    if (pheader.type != PT_LOAD)
      continue;

    // The kernel maps all physical memory regions inside its own
    // virtual address space. This virtual address space, in turn is
    // exported via /proc/kcore.

    // Each header has three pieces of relevant information:

    // File offset - The offset inside /proc/kcore where this region starts.

    // Virtual Address - The virtual address inside kernel memory
    // where the memory is mapped.

    // Physical Address - The physical address where the Virtual
    // address region is mapped by the kernel.

    // Therefore we search the exported ELF regions for the one which
    // is mapping the next required physical range. We then create an
    // AFF4 mapping between the physical memory region to the
    // /proc/kcore file address to enable reading the image.
    if (pheader.paddr != static_cast<Elf64_Addr>(
            physical_range_start[physical_range_start_index])) {
        resolver.logger->info("Skipped range {:x} - {:x} @ {:x}",
                              pheader.vaddr, pheader.memsz, pheader.off);
        continue;
    }
    physical_range_start_index++;
    resolver.logger->info("Found range {:x}/{:x} @ {:x}/{:x}",
                          pheader.paddr, pheader.memsz, pheader.vaddr,
                          pheader.off);
    map->AddRange(pheader.paddr,
                  pheader.off,
                  pheader.memsz,
                  kcore_urn);
  }

  if (map->Size() == 0) {
      resolver.logger->info("No ranges found in /proc/kcore");
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

  std::string format = GetArg<TCLAP::ValueArg<std::string>>("format")->getValue();

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
      resolver.logger->info("Adding default file collections.");
      inputs.push_back("/boot/*");

      // These files are essential for proper analysis when KASLR is enabled.
      inputs.push_back("/proc/iomem");
      inputs.push_back("/proc/kallsyms");
  }

  res = process_input();
  return res;
}

} // namespace aff4
