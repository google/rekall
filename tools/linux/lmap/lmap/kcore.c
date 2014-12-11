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

#define _LARGEFILE64_SOURCE
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "../elfrelink/elf_generic.h"
#include "../log/log.h"
#include "elf_dump.h"
#include "memory_map.h"

const char *kcore_path = "/proc/kcore";
// All physical memory is mapped between these offsets in kcore,
// see http://lxr.free-electrons.com/source/Documentation/x86/x86_64/mm.txt
const uint64_t kcore_pmem_min = 0xffff880000000000;
const uint64_t kcore_pmem_max = 0xffffc80000000000;

// Parses /proc/kcore and extracts all physical memory ranges
//
// args:
//  kcore_fd: filehandle to an open kcore file (usually /proc/kcore).
//  mm: memory map that will be filled with all physical memory ranges in kcore.
//
// return: EXIT_SUCCESS or EXIT_FAILURE.
//
int get_kcore_memory_map(int kcore_fd, MEMORY_MAP *mm) {
  Elf_Ehdr ehdr;
  Elf_Phdr phdr;
  size_t bytes_read = 0;
  int status = EXIT_FAILURE;

  memset(&ehdr, 0, sizeof(ehdr));
  memset(&phdr, 0, sizeof(phdr));
  if (lseek64(kcore_fd, 0, SEEK_SET) == -1) {
    log_print(LL_ERR, "Can't seek to start of kcore file");
    goto error;
  }
  bytes_read = read(kcore_fd, &ehdr, sizeof(ehdr));
  if (bytes_read != sizeof(ehdr)) {
    log_print(LL_ERR, "Can't read EHDR, expected %d bytes, got %d", bytes_read,
        sizeof(ehdr));
    goto error;
  }
  if (ehdr.e_phentsize != sizeof(phdr)) {
    log_print(LL_ERR, "Kernel core is incompatible with this binary. "
        "You need to use a 64-bit version of this program for 64 bit kernels");
    goto error;
  }
  for (size_t i = 0; i < ehdr.e_phnum; i++) {
    long phdr_off = ehdr.e_phoff + i * sizeof(phdr);
    if (lseek64(kcore_fd, phdr_off, SEEK_SET) == -1) {
      log_print(LL_ERR, "Can't seek to PHDR %d at offset %d", i, phdr_off);
      goto error;
    }
    bytes_read = read(kcore_fd, &phdr, sizeof(phdr));
    if (bytes_read != sizeof(phdr)) {
      log_print(LL_ERR, "Failed to read PHDR %d at offset %d", i, phdr_off);
      goto error;
    }
    // Only add the segment if it's inside the kernels physical memory mapping.
    if (phdr.p_vaddr < kcore_pmem_min || phdr.p_vaddr > kcore_pmem_max) {
      continue;
    }
    if (memory_map_append(mm, phdr.p_vaddr - kcore_pmem_min,
          phdr.p_filesz / PAGE_SIZE, phdr.p_offset)
        != EXIT_SUCCESS) {
      log_print(LL_ERR, "Failed to add physical memory region %#016lx",
          phdr.p_vaddr);
      goto error;
    }
  }
  if (mm->size > 0) {
    status = EXIT_SUCCESS;
  }
error:
  return status;
}

// Dump physical memory through /proc/kcore.
//
// The /proc/kcore device file exports a map of the kernels virtual address
// space as an ELF core dump file. Since the kernel maps all of physical memory
// into it's address space at a fixed offset, we can simply dump it from there.
//
// args:
//  dump_path: path in the fs where to write the dump to.
//
// return: EXIT_SUCCESS or EXIT_FAILURE.
//
int acquire_memory_kcore(const char *dump_path) {
  int kcore_fd = -1;
  int dump_fd = -1;
  MEMORY_MAP mm = {0};
  int status = EXIT_FAILURE;

  if (memory_map_init(&mm) != EXIT_SUCCESS) {
    log_print(LL_ERR, "Can't initialize memory map");
    goto error;
  }
  kcore_fd = open(kcore_path, O_RDONLY);
  if (kcore_fd == -1) {
    log_print(LL_ERR, "Failed to open %s", kcore_path);
    goto error_kcore;
  }
  if (get_kcore_memory_map(kcore_fd, &mm) != EXIT_SUCCESS) {
    log_print(LL_ERR, "Failed to get memory map");
    goto error_mm;
  }
  if (mm.size == 0) {
    log_print(LL_ERR, "No suitable ranges found");
    goto error_mm;
  }
  log_print(LL_LOG, "Dumping %d ranges from %s", mm.size, kcore_path);
  dump_fd = open(dump_path, O_CREAT | O_EXCL | O_WRONLY, S_IRUSR);
  if (dump_fd == -1) {
    log_print(LL_ERR, "Failed to open %s", dump_path);
    goto error_dumpfile;
  }
  if (dump_memory_elf(&mm, kcore_fd, dump_fd)) {
    log_print(LL_ERR, "Error dumping elf image of memory\n");
    goto error_dump;
  }
  log_print(LL_LOG, "Successfully wrote elf image of memory to %s\n",
            dump_path);
  status = EXIT_SUCCESS;
error_dump:
  close(dump_fd);
error_mm:
error_dumpfile:
  close(kcore_fd);
error_kcore:
  memory_map_free(&mm);
error:
  return status;
}
