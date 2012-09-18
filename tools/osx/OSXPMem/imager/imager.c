// Copyright 2012 Google Inc. All Rights Reserved.
// Author: Johannes Stüttgen (johannes.stuettgen@gmail.com)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "imager.h"

// This replaces file and ioctl apis with mock functions to enable unit testing.
// It is only active in a test build.
#ifdef PMEM_IMAGER_TEST
  #include "../test/imager_test_mock_api.h"
#endif

// Path to the device file and the driver in the filesystem.
static const char * const device_path= "/dev/pmem";

// Command line options for getopt_long().
static const char const *opt_string = "vhludrf:";
static const struct option long_opts[] = {
  {"verbose",       no_argument, NULL, 'v'},
  {"help",          no_argument, NULL, 'h'},
  {"load-kext",     no_argument, NULL, 'l'},
  {"unload-kext",   no_argument, NULL, 'u'},
  {"display-mmap",  no_argument, NULL, 'd'},
  {"format",  required_argument, NULL, 'f'},
};

// Default loglevel.
loglevel_t loglevel = STD;
// The format of the output file.
static dumpformat_t dumpformat = ELF;

// Prints debug messages to stdout.
//
// args: level signifies the maximum loglevel the message should be displayed.
//       fmt must be a format string.
//       An arbitrary amount of arguments for the format string may follow.
void print_msg(loglevel_t level, const char *fmt, ...) {
  va_list argptr;

  if (fmt == NULL) {
    return;
  }
  // Only print messages that fit in the current loglevel.
  if (loglevel < level) {
    return;
  }
  va_start(argptr, fmt);
  vprintf(fmt, argptr);
  // if fmt does not have a \n we need to flush stdout manually.
  fflush(stdout);
  va_end(argptr);
}

// Displays the command line usage and arguments help.
void display_usage(const char const *image_name) {
  print_msg(STD, "Usage: %s [OPTION...] FILE\n"
            "Dump physical address space to FILE.\n\n"
            "  -h, --help             display this help and exit\n"
            "  -v, --verbose          enable verbose logging\n"
            "  -l, --load-kext        load /dev/pmem driver and exit\n"
            "  -u, --unload-kext      unload /dev/pmem driver and exit\n"
            "  -d, --display-mmap     print physical memory map and exit\n"
            "  -f, --format [FORMAT]  set the output format (default is elf)\n"
            "\n Output formats:\n"
            "  elf                    64-bit ELF core dump with a program\n"
            "                         header per physical memory section.\n\n"
            "  mach                   64-bit MACH-O core dump with a\n"
            "                         segment load command per physical\n"
            "                         memory section.\n\n"
            "  raw                    Flat binary file where physical pages\n"
            "                         are written to their corresponding\n"
            "                         offset in the file. Memory holes and\n"
            "                         gaps in physical address space are\n"
            "                         zero-padded.\n",
            image_name);
}

// Returns true if the memory segment is accessible, meaning it is safe to read
// from it without crashing the machine.
bool segment_accessible(EfiMemoryRange *segment) {
  switch (segment->Type) {
    case kEfiReservedMemoryType:
    case kEfiMemoryMappedIO:
    case kEfiMemoryMappedIOPortSpace:
    case kEfiUnusableMemory:
      return false;
      break;
    default:
      return true;
  }
}

// Write a prepared header to the beginning of a file.
//
// args: file is an open filehandle to the output file.
//       header is a pointer to the buffer which stores the prepared header.
//       header_size is the size of the header in bytes.
//
// return: EXIT_SUCCESS or EXIT_FAILURE.
//
unsigned int write_header(int file, uint8_t *header, unsigned int header_size) {
  if (lseek(file, 0, SEEK_SET) != 0) {
    PMEM_ERROR_LOG("Could not seek to beginning of file");
    return EXIT_FAILURE;
  }
  if (write(file, header, header_size) != header_size) {
    PMEM_ERROR_LOG("Failed to write header");
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}

// Parse the mmap and dump each section into a raw file. Memory holes or
// unreadable sections like MMIO are zero padded in the dump file.
//
// args: mem_dev is an open filehandle to the pmem device file (/dev/pmem).
//       dump_file is an open filehandle to which the image will be written.
//
// return: EXIT_SUCCESS or EXIT_FAILURE.
//
unsigned int dump_memory_raw(int mem_dev, int dump_file) {
  unsigned int status = EXIT_FAILURE;
  uint64_t section = 0;
  uint64_t phys_as_size = 0;
  uint64_t bytes_imaged = 0;
  uint8_t *mmap = NULL;
  unsigned int mmap_size = 0;
  unsigned int mmap_desc_size = 0;

  if (get_mmap(&mmap, &mmap_size, &mmap_desc_size, mem_dev) == EXIT_FAILURE) {
    print_msg(STD, "Failed to obtain memory map\n");
    goto error_malloc;
  }
  // Iterate over each section in the physical memory map and write it to disk.
  for (section = 0; section < mmap_size / mmap_desc_size; section++) {
    EfiMemoryRange *segment = (EfiMemoryRange *)(
        mmap + (section * mmap_desc_size));
    // dump the segment
    uint64_t start = segment->PhysicalStart;
    uint64_t size = segment->NumberOfPages * PAGE_SIZE;
    print_msg(STD, "[%016llx - %016llx] %s ", start, start + size,
              physmem_type_tostring(segment->Type));
    if (segment_accessible(segment)) {
      if (write_segment(segment, mem_dev, dump_file, start) == EXIT_FAILURE) {
        print_msg(STD, "Failed to dump segment %d\n", section);
        goto error;
      }
      print_msg(STD, "[WRITTEN]\n");
      // calculate statistics
      bytes_imaged += size;
      uint64_t end_addr = segment->PhysicalStart +
                          segment->NumberOfPages * PAGE_SIZE;
      if (end_addr > phys_as_size) {
        phys_as_size = end_addr;
      }
    } else {
      // Zero pad this region as it is inaccessible
      if (lseek(dump_file, start + size, SEEK_SET) != start + size) {
        PMEM_ERROR_LOG("Could not zero pad inaccessible segment in dump file");
        goto error;
      }
      print_msg(STD, "[PADDED]\n");
    }
  }
  print_msg(STD, "Acquired %lld pages (%lld bytes)\n",
            bytes_imaged/PAGE_SIZE, bytes_imaged);
  print_msg(STD, "Size of physical address space: %lld bytes (%lld segments)\n",
            phys_as_size, section);
  status = EXIT_SUCCESS;
error:
    free(mmap);
error_malloc:
  return status;
}

// Write a segment of physical memory into a binary file. This segment must be
// accessible, otherwise the function will return 0.
//
// args: segment is a struct describing the position and size of the segment.
//       mem_dev is an open filehandle to the /dev/pmem device.
//       dump_file is an open filehandle to the image file.
//
// return: the number of bytes written.
//
unsigned int write_segment(EfiMemoryRange *segment, int mem_dev,
                           int dump_file, uint64_t file_offset) {
  unsigned int status = EXIT_FAILURE;
  uint64_t segment_size = segment->NumberOfPages * PAGE_SIZE;
  uint64_t page = segment->PhysicalStart;
  uint64_t end = segment->PhysicalStart + segment_size;
  uint8_t *page_buf = NULL;

  page_buf = (uint8_t *)malloc(PAGE_SIZE);
  if (page_buf == NULL) {
    print_msg(STD, "Could not allocate memory for page buffer\n");
    goto error_malloc;
  }
  if (segment_accessible(segment)) {
    // Dump contiguous segments one page at a time
    while (page < end) {
      if (lseek(mem_dev, page, SEEK_SET) != page) {
        PMEM_ERROR_LOG("Could not seek to page in memory device");
        goto error;
      }
      if (read(mem_dev, page_buf, PAGE_SIZE) != PAGE_SIZE) {
        PMEM_ERROR_LOG("Failed to read page");
        goto error;
      }
      // Copy the page to the indicated offset in the mach-o file
      if (lseek(dump_file, file_offset, SEEK_SET) != file_offset) {
        PMEM_ERROR_LOG("Could not seek to segment in dump file");
        goto error;
      }
      if (write(dump_file, page_buf, PAGE_SIZE) != PAGE_SIZE) {
        PMEM_ERROR_LOG("Failed to write page");
        goto error;
     }
      // Advance the read and write pointers
      page += PAGE_SIZE;
      file_offset += PAGE_SIZE;
    }
  } else {
    // This segment cannot be imaged, you shouldn't have called this function.
    PMEM_ERROR_LOG("Illegal segment type, unable to copy");
    goto error;
  }
  status = EXIT_SUCCESS;
error:
  free(page_buf);
error_malloc:
  return status;
}

// Write a prepared mach-o header to the beginning of a file.
//
// args: file is an open filehandle to the output file.
//       header is a pointer to the buffer which stores the prepared header.
//       header_size is the size of the header in bytes.
//
unsigned int write_macho_header(int file, uint8_t *header, unsigned int header_size) {
  if (lseek(file, 0, SEEK_SET) != 0) {
    PMEM_ERROR_LOG("Could not seek to beginning of mach-o file");
    return EXIT_FAILURE;
  }
  if (write(file, header, header_size) != header_size) {
        PMEM_ERROR_LOG("Failed to write mach-o header");
        return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}

// Initialize a mach-o header with default values for a core dump file
// and a specific number of segment load commands.
//
// args: header is a pointer to the mach_header_64 struct to initialize.
//       num_segments is the number of segment_load_command_64 structs to add to
//       the header.
//
void prepare_macho_header(mach_header_t *header, unsigned int num_segments) {
  // All values that are unset will be zero
  bzero(header, sizeof(mach_header_t));
  // We create a 64 bit core dump file with one segment
  // for each physical memory segment.
  header->magic = MH_MAGIC_64;
  header->cputype = CPU_TYPE_X86_64;
  header->cpusubtype = CPU_SUBTYPE_I386_ALL;
  header->filetype = MH_CORE;
  header->ncmds = num_segments;
  header->sizeofcmds = num_segments * sizeof(segment_command_t);
}

// Initialize a mach-o segment load command with the data from an EFI segment
// descriptor.
//
// args: load_command is a pointer to the segment_load_command_64 struct to
//       initialize.
//       segment is a pointer to the EFI segment descriptor to copy data from.
//       file_offset is the raw offset into the mach-o file the segment will be
//       actually stored in.
//
// return: EXIT_SUCCESS or EXIT_FAILURE.
//
void prepare_macho_segment(segment_command_t *load_command,
                           EfiMemoryRange *segment, uint64_t file_offset) {
  uint64_t segment_size = segment->NumberOfPages * PAGE_SIZE;

  // All values that are unset will be zero
  bzero(load_command, sizeof(segment_command_t));
  load_command->cmd = LC_SEGMENT_64;
  load_command->cmdsize = sizeof(struct segment_command_64);
  // the segname field is a 16 byte fixed length ascii string.
  memcpy(&(load_command->segname), physmem_type_tostring(segment->Type), 16);
  load_command->vmaddr = segment->PhysicalStart;
  load_command->vmsize = segment_size;
  if (segment_accessible(segment)) {
    load_command->fileoff = file_offset;
    load_command->filesize = segment_size;
  } else {
    // The segment is inaccessible, thus it is not stored in the image.
    load_command->fileoff = 0;
    load_command->filesize = 0;
  }
  // The flags only matter to the loader anyways, so we use this field to store
  // the type enum of the segment to simplify processing of the image.
  load_command->flags = segment->Type;
  load_command->nsects = 0;
}

// Parse the mmap and dump each section into a mach-o core dump file.
// Memory holes are ignored and unreadable sections like MMIO are written as
// empty segments. For each segment a load command is created in the mach-o
// file, that documents the physical address range it occupied.
//
// args: mem_dev is an open filehandle to the pmem device file (/dev/pmem).
//       dump_file is an open filehandle to which the image will be written.
//
// return: EXIT_SUCCESS or EXIT_FAILURE.
//
unsigned int dump_memory_macho(int mem_dev, int dump_file) {
  unsigned int status = EXIT_FAILURE;
  uint64_t section = 0;
  uint64_t file_offset = 0;
  uint64_t phys_as_size = 0;
  uint64_t bytes_imaged = 0;
  int num_segments = 0;
  unsigned int headers_bufsize = 0;
  uint8_t *mach_headers_buf = NULL;
  EfiMemoryRange *segment = NULL;
  mach_header_t *mach_header = NULL;
  segment_command_t *load_command = NULL;
  uint8_t *mmap = NULL;
  unsigned int mmap_size = 0;
  unsigned int mmap_desc_size = 0;

  if (get_mmap(&mmap, &mmap_size, &mmap_desc_size, mem_dev) == EXIT_FAILURE) {
    PMEM_ERROR_LOG("Failed to obtain memory map");
    goto error_mmap;
  }
  if (mmap_size < mmap_desc_size || mmap_size % mmap_desc_size ||
      mmap_desc_size == 0) {
    PMEM_ERROR_LOG("Memory map corrupted, could not dump memory");
    goto error_mmap_corrupt;
  }
  num_segments = mmap_size / mmap_desc_size;
  headers_bufsize = (
      sizeof(mach_header_t) + num_segments * sizeof(segment_command_t));
  segment = (EfiMemoryRange *)mmap;

  if ((mach_headers_buf = (uint8_t *)malloc(headers_bufsize)) == NULL) {
    PMEM_ERROR_LOG("Could not allocate memory for mach-o headers");
    goto error_headers;
  }
  // The mach-o header is at the beginning of the buffer
  mach_header = (mach_header_t *)mach_headers_buf;
  // The load commands come right after the header
  load_command = (segment_command_t *)(mach_headers_buf +
                                       sizeof(mach_header_t));
  prepare_macho_header(mach_header, num_segments);
  // Data will be written right after the header and load commands
  file_offset += headers_bufsize;
  // Iterate over each section in the physical memory map and write it to disk.
  for (section = 0; section < num_segments; section++) {
    uint64_t segment_size = segment->NumberOfPages * PAGE_SIZE;
    // prepare the load command for this segment in the macho-o header
    prepare_macho_segment(load_command, segment, file_offset);
    print_msg(STD, "[%016llx - %016llx] %s ", segment->PhysicalStart,
              segment->PhysicalStart + segment_size,
              physmem_type_tostring(segment->Type));
    // Only dump accessible segments
    if (segment_accessible(segment)) {
      if (write_segment(segment, mem_dev, dump_file, file_offset) == (
            EXIT_FAILURE)) {
        print_msg(STD, "Failed to dump segment %d\n", section);
        goto error;
      }
      file_offset += segment_size;
      bytes_imaged += segment_size;
      print_msg(STD, "[WRITTEN]\n");
    } else {
      print_msg(STD, "[SKIPPED]\n");
    }
    // Advance to the next segment, taking padding in the EFI implementation
    // into account (might not be the same as gcc's).
    segment = (EfiMemoryRange *)(((uint8_t *)segment) + mmap_desc_size);
    load_command++;
    // Calculate statistics
    uint64_t end_addr = segment->PhysicalStart +
                        segment->NumberOfPages * PAGE_SIZE;
    if (end_addr > phys_as_size) {
      phys_as_size = end_addr;
    }
  }
  write_header(dump_file, mach_headers_buf, headers_bufsize);
  print_msg(STD, "Acquired %lld pages (%lld bytes)\n",
            bytes_imaged / PAGE_SIZE, bytes_imaged);
  print_msg(STD, "Size of physical address space: %lld bytes (%lld segments)\n",
            phys_as_size, section);
  status = EXIT_SUCCESS;
error:
  free(mach_headers_buf);
error_headers:
error_mmap_corrupt:
  free(mmap);
error_mmap:
  return status;
}

// Parse the mmap and dump each section into an elf core dump file.
// Memory holes are ignored and unreadable sections like MMIO are written as
// empty segments. For each segment a program header is created in the elf
// file, that documents the physical address range it occupied.
//
// args: mem_dev is an open filehandle to the pmem device file (/dev/pmem).
//       dump_file is an open filehandle to which the image will be written.
//
// return: EXIT_SUCCESS or EXIT_FAILURE.
//
unsigned int dump_memory_elf(int mem_dev, int dump_file) {
  unsigned int status = EXIT_FAILURE;
  uint64_t section = 0;
  uint64_t file_offset = 0;
  uint64_t phys_as_size = 0;
  uint64_t bytes_imaged = 0;
  int num_segments = 0;
  unsigned int headers_bufsize = 0;
  uint8_t *elf_headers_buf = NULL;
  EfiMemoryRange *segment = NULL;
  elf64_ehdr *elf_header = NULL;
  elf64_phdr *program_header = NULL;
  uint8_t *mmap = NULL;
  unsigned int mmap_size = 0;
  unsigned int mmap_desc_size = 0;

  if (get_mmap(&mmap, &mmap_size, &mmap_desc_size, mem_dev) == EXIT_FAILURE) {
    PMEM_ERROR_LOG("Failed to obtain memory map");
    goto error_mmap;
  }
  if (mmap_size < mmap_desc_size || mmap_size % mmap_desc_size ||
      mmap_desc_size == 0) {
    PMEM_ERROR_LOG("Memory map corrupted, could not dump memory");
    goto error_mmap_corrupt;
  }
  num_segments = mmap_size / mmap_desc_size;
  headers_bufsize = (
      sizeof(elf64_ehdr) + num_segments * sizeof(elf64_phdr));
  segment = (EfiMemoryRange *)mmap;

  if ((elf_headers_buf = (uint8_t *)malloc(headers_bufsize)) == NULL) {
    PMEM_ERROR_LOG("Could not allocate memory for mach-o headers");
    goto error_headers;
  }
  // The ELF header is at the beginning of the buffer
  elf_header = (elf64_ehdr *)elf_headers_buf;
  // The program headers come right after the elf header
  program_header = (elf64_phdr *)(elf_headers_buf +
                                       sizeof(elf64_ehdr));
  prepare_elf_header(elf_header, num_segments);
  // Data will be written right after the header and load commands
  file_offset += headers_bufsize;
  // Iterate over each section in the physical memory map and write it to disk.
  for (section = 0; section < num_segments; section++) {
    uint64_t segment_size = segment->NumberOfPages * PAGE_SIZE;
    prepare_elf_program_header(program_header, segment, file_offset);
    print_msg(STD, "[%016llx - %016llx] %s ", segment->PhysicalStart,
              segment->PhysicalStart + segment_size,
              physmem_type_tostring(segment->Type));
    // Only dump accessible segments
    if (segment_accessible(segment)) {
      if (write_segment(segment, mem_dev, dump_file, file_offset) == (
            EXIT_FAILURE)) {
        print_msg(STD, "Failed to dump segment %d\n", section);
        goto error;
      }
      file_offset += segment_size;
      bytes_imaged += segment_size;
      print_msg(STD, "[WRITTEN]\n");
    } else {
      print_msg(STD, "[SKIPPED]\n");
    }
    // Advance to the next segment, taking padding in the EFI implementation
    // into account (might not be the same as gcc's).
    segment = (EfiMemoryRange *)(((uint8_t *)segment) + mmap_desc_size);
    program_header++;
    // Calculate statistics
    uint64_t end_addr = segment->PhysicalStart +
                        segment->NumberOfPages * PAGE_SIZE;
    if (end_addr > phys_as_size) {
      phys_as_size = end_addr;
    }
  }
  write_header(dump_file, elf_headers_buf, headers_bufsize);
  print_msg(STD, "Acquired %lld pages (%lld bytes)\n",
            bytes_imaged / PAGE_SIZE, bytes_imaged);
  print_msg(STD, "Size of physical address space: %lld bytes (%lld segments)\n",
            phys_as_size, section);
  status = EXIT_SUCCESS;
error:
  free(elf_headers_buf);
error_headers:
error_mmap_corrupt:
  free(mmap);
error_mmap:
  return status;
}

// Initialize an ELF header with default values for a core dump file
// and a specific number of program headers.
//
// args: header is a pointer to the mach_header_64 struct to initialize.
//       num_segments is the number of program headers to add to this header.
//
void prepare_elf_header(elf64_ehdr *header, unsigned int num_segments) {
  // All values that are unset will be zero
  bzero(header, sizeof(elf64_ehdr));
  // We create a 64 bit core dump file with one section
  // for each physical memory segment.
  header->e_ident[0] = ELFMAG0;
  header->e_ident[1] = ELFMAG1;
  header->e_ident[2] = ELFMAG2;
  header->e_ident[3] = ELFMAG3;
  header->e_ident[4] = ELFCLASS64;
  header->e_ident[5] = ELFDATA2LSB;
  header->e_ident[6] = EV_CURRENT;
  header->e_type     = ET_CORE;
  header->e_machine  = EM_X86_64;
  header->e_version  = EV_CURRENT;
  header->e_phoff    = sizeof(elf64_ehdr);
  header->e_ehsize   = sizeof(elf64_ehdr);
  header->e_phentsize= sizeof(elf64_phdr);
  header->e_phnum    = num_segments;
  header->e_shentsize= sizeof(elf64_shdr);
}

// Initialize an ELF program header with data from an EFI segment descriptor.
//
// args: program_header is a pointer to an elf64_phdr struct to initialize.
//       segment is a pointer to the EFI segment descriptor to copy data from.
//       file_offset is the raw offset into the mach-o file the segment will be
//       actually stored in.
//
void prepare_elf_program_header(elf64_phdr *program_header,
                                EfiMemoryRange *segment, uint64_t file_offset) {
  uint64_t segment_size = segment->NumberOfPages * PAGE_SIZE;
  // All values that are unset will be zero
  bzero(program_header, sizeof(elf64_phdr));
  program_header->p_type = PT_LOAD;
  program_header->p_paddr = segment->PhysicalStart;
  program_header->p_memsz = segment_size;
  program_header->p_align = PAGE_SIZE;
  // Flags are only used by the loader,
  // so we can use this field to store the segment type
  program_header->p_flags = segment->Type;
  if (segment_accessible(segment)) {
    program_header->p_offset = file_offset;
    program_header->p_filesz = segment_size;
  }
}

// Send an ioctl to the driver to get the physical memory map.
// Will also retrieve the size of the map and its descriptors.
// This function will allocate memory for mmap, make sure you free it.
//
// args: mmap is a pointer to a pointer that will recieve the memory map.
//       mmap_size is a pointer that will recieve the size of the memory map.
//       mmap_desc_size is a pointer that will recieve the size of an individual
//       memory descriptor in the memory map.
//       device_file is an open file descriptor to the pmem device file.
//
// return: EXIT_SUCCESS and EXIT_FAILURE.
//
unsigned int get_mmap(uint8_t **mmap, unsigned int *mmap_size,
                      unsigned int *mmap_desc_size, int device_file) {
  int err;
  int status = EXIT_FAILURE;

  err = ioctl(device_file, PMEM_IOCTL_GET_MMAP_SIZE, mmap_size);
  if (err != 0) {
    PMEM_ERROR_LOG("Error getting size of memory map");
    goto error;
  }
  err = ioctl(device_file, PMEM_IOCTL_GET_MMAP_DESC_SIZE, mmap_desc_size);
  if (err != 0) {
    PMEM_ERROR_LOG("Error getting size of memory map descriptors");
    goto error;
  }
  print_msg(DBG, "Recieved memory map, size:%d bytes (descriptors: %d)\n",
            *mmap_size, *mmap_desc_size);
  // Allocate buffer of apropriate size.
  *mmap = (uint8_t *)malloc(*mmap_size);
  if (*mmap == NULL) {
    PMEM_ERROR_LOG("Could not allocate buffer for memory map");
    goto error;
  }
  // Ask the driver to fill it with the physical memory map.
  if ((err = ioctl(device_file, PMEM_IOCTL_GET_MMAP, mmap)) != 0) {
    PMEM_ERROR_LOG("Error getting memory map");
    free(*mmap);
    goto error;
  }
  status = EXIT_SUCCESS;
error:
  return status;
}

// Send an ioctl to the driver to get the kernels directory table base.
//
// args: fd is an open file handle to the pmem drivers device file.
//       dtb is a pointer to the uint64_t the result will be written to.
//
// return: EXIT_SUCCESS or EXIT_FAILURE
//
unsigned int get_dtb(int fd, uint64_t *dtb) {
  if (fd < 0) {
    print_msg(STD, "invalid file handle for driver device file");
    return EXIT_FAILURE;
  }
  if (ioctl(fd, PMEM_IOCTL_GET_DTB, dtb) != 0) {
    print_msg(STD, "Failed to get dtb from driver\n");
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}

// Map a given integer to a string describing the type of memory.
//
// args: type is the EfiMemoryRange.Type field
//
// return: pointer to a text representation of the given type.
//
const char const *physmem_type_tostring(int type) {
  static const char const *physmem_type[] = {"Reserved       ",   // 0x0
                                             "Loader Code    ",   // 0x1
                                             "Loader Data    ",   // 0x2
                                             "BS Code        ",   // 0x3
                                             "BS Data        ",   // 0x4
                                             "RTS Code       ",   // 0x5
                                             "RTS Data       ",   // 0x6
                                             "Conventional   ",   // 0x7
                                             "Unusable       ",   // 0x8
                                             "ACPI Reclaim   ",   // 0x9
                                             "ACPI Memory NVS",   // 0xA
                                             "MMIO           ",   // 0xB
                                             "MMIO Port Space",   // 0xC
                                             "Pal Code       ",   // 0xD
                                             "Max Memory Type",   // 0xE
                                             "Unknown        "};  // >0xE
  // Check for illegal values and normalize them
  if (type > 0xE) {
    type = 0xE;
  }
  return physmem_type[type];
}

// Converts the binary memory map into a human readable form.
//
// args: mmap is a pointer to the binary memory map
//       mmap_size is the number of entries in the memory map
//       mmap_entry_size is the size in bytes of an individual entry in the map
//
// return: A pointer to a character buffer containing a textual version of the
//         memory map. The caller is responsible of freeing it. The string is
//         guaranteed to be zero terminated, so buffer size is strlen() + 1.
//
char *mmap_tostring(uint8_t *mmap,
                    const unsigned int mmap_size,
                    const unsigned int mmap_entry_size) {
  // Keep this below 64 characters or adjust max_line_len
  static const char * const header = "Memory Type             Start Addr"
                                     "       End Addr\n";
  unsigned int max_line_len = 64;
  unsigned int line_buf_written = 0;
  uint64_t phys_addr_space_size = 0;
  unsigned int section = 0;
  const char *section_type = NULL;
  // Buffer that holds a text representation of the physical memoy map. will be
  // returned to the caller, so we don't free it here. +1 is for the header.
  char *mmap_buf = NULL;
  mmap_buf = (char *)malloc(mmap_size * (max_line_len + 1));
  if (mmap_buf == NULL) {
    print_msg(STD, "Could not allocate memory for mmap text buffer\n");
    return NULL;
  }
  // Start the string buffer with the header
  strncpy(mmap_buf, header, max_line_len);
  line_buf_written += strnlen(header, max_line_len);
  // points to the current segment in the memory map
  EfiMemoryRange *segment = (EfiMemoryRange *)mmap;
  // Fill it with a new line for each memory segment
  for (section = 0; section < mmap_size / mmap_entry_size; section++) {
    section_type = physmem_type_tostring(segment->Type);
    uint64_t end_addr = (
        segment->PhysicalStart + (segment->NumberOfPages * PAGE_SIZE));
    int printed_chars = snprintf(mmap_buf + line_buf_written - 1,
                                 max_line_len, "\n%s %016llx %016llx",
                                 section_type, segment->PhysicalStart,
                                 end_addr);
    if (printed_chars < 0) {
      print_msg(STD, "Warning, failed to format entry %d in memory map",
                section);
    }
    if (printed_chars <= max_line_len && printed_chars >= 0) {
      line_buf_written += printed_chars;
    } else {
      print_msg(STD, "Warning, entry %d in memory map was truncated", section);
      line_buf_written += max_line_len;
    }
    // Advance to the next segment, taking padding in the EFI implementation
    // into account (might not be the same as gcc's).
    segment = (EfiMemoryRange *)(((uint8_t *)segment) + mmap_entry_size);
    // Store size of physical address space, this is equal to the file size of
    // the memory dump if holes are zero padded.
    if (end_addr > phys_addr_space_size) {
      phys_addr_space_size = end_addr;
    }
  }
  // Make sure the buffer is zero terminated
  mmap_buf[line_buf_written - 1] = '\0';
  print_msg(STD, "Size of physical address space: %lld bytes (%d segments)\n",
           phys_addr_space_size, section);
  return mmap_buf;
}

// Load the driver, get the physical memory map, convert it to a text
// representation and finally print it out to the user. Will unload the driver
// after use and is supposed to be used as an invocation from command line
// arguments.
unsigned int display_mmap(const char const *device_file_path) {
  unsigned int status = EXIT_FAILURE;
  int device_file = -1;
  uint8_t *mmap = 0;
  unsigned int mmap_size = 0;
  unsigned int mmap_desc_size = 0;

  if (load_kext()) {
    PMEM_ERROR_LOG("Failed to load kext");
    goto error_kext;
  }
  device_file = open(device_file_path, O_RDWR);
  if (device_file == -1) {
    PMEM_ERROR_LOG("Failed to open device file %s", device_file_path);
    goto error_device;
  }
  if (get_mmap(&mmap, &mmap_size, &mmap_desc_size, device_file) == (
        EXIT_FAILURE)) {
    print_msg(STD, "Error, could not get memory map from driver");
    goto error_mmap;
  }
  char *map = mmap_tostring(mmap, mmap_size, mmap_desc_size);
  if (map == NULL) {
    PMEM_ERROR_LOG("Failed to convert memory map to string");
    goto error_map;
  }
  print_msg(STD, "\n%s\n", map);
  status = EXIT_SUCCESS;
  free(map);
error_map:
  free(mmap);
error_mmap:
  close(device_file);
error_device:
  if (unload_kext()) {
    PMEM_ERROR_LOG("Failed to unload kext");
    exit(EXIT_FAILURE);
  }
error_kext:
  return status;
}

// Will call the IOKit to load the pmem kext from the current working directory.
unsigned int load_kext(void) {
  int status = EXIT_SUCCESS;
  struct stat s;

  stat(PMEM_KEXT_PATH, &s);
  if (s.st_uid != 0 || s.st_gid != 0) {
    print_msg(STD, "Can't load kext %s, as it is not owned by root:wheel\n",
              PMEM_KEXT_PATH);
    return EXIT_FAILURE;
  }
  print_msg(DBG, "Loading kext from %s\n", PMEM_KEXT_PATH);
  CFStringRef kext_path = CFSTR(PMEM_KEXT_PATH);
  CFURLRef kext_url = CFURLCreateWithFileSystemPath(kCFAllocatorDefault,
                                                   kext_path,
                                                   kCFURLPOSIXPathStyle,
                                                   true);
  if (KextManagerLoadKextWithURL(kext_url, NULL) != kOSReturnSuccess) {
    print_msg(STD, "Cannot load kext %s\n", PMEM_KEXT_PATH);
    status = EXIT_FAILURE;
  }
  CFRelease(kext_url);
  CFRelease(kext_path);
  return status;
}

// Will call the IOKit to unload the pmem kext.
unsigned int unload_kext(void) {
  int status = EXIT_SUCCESS;

  print_msg(DBG, "Unloading kext %s\n", PMEM_KEXT_IDENTIFIER);
  CFStringRef kext_id = CFSTR(PMEM_KEXT_IDENTIFIER);
  if (KextManagerUnloadKextWithIdentifier(kext_id) != kOSReturnSuccess) {
    print_msg(STD, "Cannot unload kext %s\n", PMEM_KEXT_IDENTIFIER);
    status = EXIT_FAILURE;
  }
  CFRelease(kext_id);
  return status;
}

// Main dispatch function for memory dumps. Will load the driver, acquire the
// memory map and invoke the correct imaging function. Also cleans up after
// itself, so it returns void.
//
// args: dump_file_path is the path to the desired memory dump file.
unsigned int dump_memory(const char const *dump_file_path,
                         const char const *device_file_path) {
  int mem_dev = -1;
  int dump_file = -1;
  uint64_t kernel_dtb = 0;
  int status = EXIT_FAILURE;

  if (load_kext()) {
    PMEM_ERROR_LOG("Failed to load kext");
    goto error_kext;
  }
  if ((mem_dev = open(device_file_path, O_RDONLY)) == -1) {
    PMEM_ERROR_LOG("Error opening physical memory device");
    goto error_memdev;
  }
  if ((dump_file =
       open(dump_file_path, O_RDWR | O_CREAT | O_TRUNC, 0440)) == -1) {
    PMEM_ERROR_LOG("Error opening dump file");
    goto error_dumpfile;
  }
  // Now dump the memory in the preferred format
  switch (dumpformat) {
    case RAW_PADDED:
      if (dump_memory_raw(mem_dev, dump_file)) {
        print_msg(STD, "Error dumping raw image of memory\n");
        goto error;
      }
      print_msg(STD, "Successfully wrote raw image of memory to %s\n",
                dump_file_path);
      break;

    case MACH_O:
      if (dump_memory_macho(mem_dev, dump_file)) {
        print_msg(STD, "Error dumping mach-o image of memory\n");
        goto error;
      }
      print_msg(STD, "Successfully wrote mach-o image of memory to %s\n",
                dump_file_path);
      break;

    case ELF:
      if (dump_memory_elf(mem_dev, dump_file)) {
        print_msg(STD, "Error dumping elf image of memory\n");
        goto error;
      }
      print_msg(STD, "Successfully wrote elf image of memory to %s\n",
                dump_file_path);
      break;
  }
  if (get_dtb(mem_dev, &kernel_dtb) == EXIT_FAILURE) {
    print_msg(STD, "Error, could not get dtb from driver\n");
    goto error;
  }
  print_msg(STD, "Kernel directory table base: %#016llx\n", kernel_dtb);
  status = EXIT_SUCCESS;
error:
  close(dump_file);
error_dumpfile:
  close(mem_dev);
error_memdev:
  if (unload_kext() == EXIT_FAILURE) {
    PMEM_ERROR_LOG("Failed to unload kext");
    status = EXIT_FAILURE;
  }
error_kext:
  return status;
}

// Use getopts_long() to parse commandline arguments and dispatch the
// appropriate functions.
int main(int argc, char **argv) {
  int opt = 0;
  int long_index = 0;
  unsigned int status = EXIT_SUCCESS;

  while ((opt =
          getopt_long(argc, argv, opt_string, long_opts, &long_index)) != -1) {
    switch (opt) {
      case 'v': // Enable verbose logging
        loglevel = DBG;
        break;

      case 'f': // Set output format
        if (strcmp(optarg, "elf") == 0) {
          dumpformat = ELF;
          break;
        }
        if (strcmp(optarg, "mach") == 0) {
          dumpformat = MACH_O;
          break;
        }
        if (strcmp(optarg, "raw") == 0) {
          dumpformat = RAW_PADDED;
          break;
        }
        print_msg(STD, "Output format %s not supported!\n", optarg);
        display_usage(argv[0]);
        status = EXIT_FAILURE;
        break;

      case 'h': // Display help and exit
        display_usage(argv[0]);
        goto end;

      case 'u': // Unload driver and exit
        status = unload_kext();
        goto end;

      case 'l': // Load driver and exit
        status = load_kext();
        goto end;

      case 'd': // Display memory map and exit
        status = display_mmap(device_path);
        goto end;

      default:
        display_usage(argv[0]);
        status = EXIT_FAILURE;
        goto end;
    }
  }
  // There should be exactly one argument left.
  if (argc - optind != 1) {
    display_usage(argv[0]);
    status = EXIT_FAILURE;
    goto end;
  }
  // the last remaining argument is the name of the dumpfile.
  status = dump_memory(argv[optind], device_path);
end:
  return status;
}
