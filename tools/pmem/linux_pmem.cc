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

AFF4Status LinuxPmemImager::ParseKcore(vector<KCoreRange> &ranges) {
  LOG(INFO) << "Will parse /proc/kcore";
  AFF4ScopedPtr<AFF4Stream> stream = resolver.AFF4FactoryOpen<AFF4Stream>(
      "/proc/kcore");

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
      KCoreRange range;
      range.kcore_offset = pheader.vaddr;
      range.file_offset = pheader.off;
      range.phys_offset = pheader.vaddr - 0xffff880000000000ULL;
      range.length = pheader.memsz;

      ranges.push_back(range);
    }
  }

  if (ranges.size() == 0) {
    LOG(INFO) << "No ranges found in /proc/kcore";
    return NOT_FOUND;
  }

  return STATUS_OK;
}


AFF4Status LinuxPmemImager::ImagePhysicalMemoryToElf() {
  std::cout << "Imaging memory to an Elf file.\n";

  vector<KCoreRange> ranges;
  AFF4Status res = ParseKcore(ranges);
  if (res != STATUS_OK)
    return res;

  string output_path = GetArg<TCLAP::ValueArg<string>>("output")->getValue();
  URN output_urn(URN::NewURNFromFilename(output_path));

  // Always truncate output to 0 when writing an elf file (these do not support
  // appending).
  resolver.Set(output_urn, AFF4_STREAM_WRITE_MODE, new XSDString("truncate"));

  AFF4ScopedPtr<AFF4Stream> output_stream = resolver.AFF4FactoryOpen
      <AFF4Stream>(output_urn);

  if (!output_stream) {
    LOG(ERROR) << "Failed to create output file: " <<
        output_urn.SerializeToString();

    return IO_ERROR;
  }

  Elf64_Ehdr header = {
    .ident = {ELFMAG0, ELFMAG1, ELFMAG2, ELFMAG3, ELFCLASS64,
              ELFDATA2LSB, EV_CURRENT},
    .type = ET_CORE,
    .machine = EM_X86_64,
    .version = EV_CURRENT,
  };

  header.phoff    = sizeof(Elf64_Ehdr);
  header.phentsize = sizeof(Elf64_Phdr);
  header.ehsize = sizeof(Elf64_Ehdr);
  header.phentsize = sizeof(Elf64_Phdr);

  header.phnum = ranges.size();
  header.shentsize = sizeof(Elf64_Shdr);
  header.shnum = 0;

  output_stream->Write(reinterpret_cast<char *>(&header), sizeof(header));

  // Where we start writing data: End of ELF header plus one physical header per
  // range.
  uint64 file_offset = sizeof(Elf64_Ehdr) + ranges.size() * sizeof(Elf64_Phdr);

  for (auto range : ranges) {
    Elf64_Phdr pheader = {};

    pheader.type = PT_LOAD;
    pheader.paddr = range.phys_offset;
    pheader.memsz = range.length;
    pheader.align = 1;
    pheader.flags = PF_R;
    pheader.off = file_offset;
    pheader.filesz = range.length;

    // Move the file offset by the size of this run.
    file_offset += range.length;

    if (output_stream->Write(reinterpret_cast<char *>(&pheader),
                             sizeof(pheader)) < 0) {
      return IO_ERROR;
    }
  }

  AFF4ScopedPtr<AFF4Stream> kcore_stream = resolver.AFF4FactoryOpen<AFF4Stream>(
      "/proc/kcore");
  if (!kcore_stream)
    return IO_ERROR;

  for (auto range : ranges) {
    kcore_stream->Seek(range.file_offset, SEEK_SET);
    res = kcore_stream->CopyToStream(
        *output_stream, range.length,
        std::bind(&LinuxPmemImager::progress_renderer, this,
                  std::placeholders::_1, std::placeholders::_2));

    if (res != STATUS_OK)
      return res;
  }

  return STATUS_OK;
}


AFF4Status LinuxPmemImager::ImagePhysicalMemory() {
  std::cout << "Imaging memory\n";
  vector<KCoreRange> ranges;
  AFF4Status res = ParseKcore(ranges);

  if (res != STATUS_OK)
    return res;

  LOG(INFO) << "Parsed " << ranges.size() << " ranges";
  res = ImageKcoreToMap(ranges);
  if (res != STATUS_OK)
    return res;

  // Also capture these files by default.
  if (inputs.size() == 0) {
    LOG(INFO) << "Adding default file collections.";
    inputs.push_back("/boot/*");
  }

  res = process_input();
  return res;
}


AFF4Status LinuxPmemImager::ImageKcoreToMap(vector<KCoreRange> &ranges) {
  URN output_urn;
  AFF4Status res = GetOutputVolumeURN(output_urn);
  if (res != STATUS_OK)
    return res;

  URN map_urn = output_urn.Append("/proc/kcore");
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

  AFF4ScopedPtr<AFF4Stream> kcore_stream = resolver.AFF4FactoryOpen<AFF4Stream>(
      "/proc/kcore");
  if (!kcore_stream)
    return IO_ERROR;

  for (auto range : ranges) {
    kcore_stream->Seek(range.file_offset, SEEK_SET);
    map_stream->Seek(range.phys_offset, SEEK_SET);
    res = kcore_stream->CopyToStream(
        *map_stream, range.length,
        std::bind(&LinuxPmemImager::progress_renderer, this,
                  std::placeholders::_1, std::placeholders::_2));

    if (res != STATUS_OK)
      return res;
  }

  return STATUS_OK;
}
