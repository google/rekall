// This is LMAP, the Linux Memory Acquisition Parasite.
//
// This program will find a suitable kernel module (host) in /lib/modules and
// inject a physical memory acquisition driver into it. It will then hijack the
// init and cleanup functions so that the physical memory driver is initialized
// instead of the host module.
//
// Copyright 2013 Google Inc. All Rights Reserved.
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

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "lkm_control.h"
#include "lmap_config.h"
#include "memory_map.h"

#include "../elfrelink/elfrelink.h"
#include "../elfrelink/elf_object.h"
#include "../log/log.h"

#define ARRAY_SIZE(x) ((sizeof x) / (sizeof *x))

typedef enum WORKMODE_T {
  WM_NONE,
  WM_FIND,
  WM_LOAD,
  WM_DUMP,
  WM_MMAP,
  WM_ACQUIRE
} WORKMODE;

// Commandline arguments and configuration
typedef struct ARGS_T {
  const char *out_path;
  char *host_path;
  char *host_name;
  char *module_path;
  char *lib_path;
  char *acquisition_path;
  size_t module_size;
  size_t host_path_len;
  WORKMODE mode;
  size_t injection_idx;
} ARGS;

static ARGS args = {
  .out_path = "infected_module.ko",
  .host_path = NULL,
  .host_name = NULL,
  .module_path = NULL,
  .lib_path = NULL,
  .host_path_len = 0,
  .mode = WM_NONE,
  .injection_idx = 0
};

// Describes a relocation inside a struct
typedef struct RELA_STRUCT_T {
  char *container; // containing struct
  char *symbol; // symbol relocated into the struct
} RELA_STRUCT;

// Describes a relocation patch
typedef struct RELA_PATCH_T {
  RELA_STRUCT target_rela;
  char *hook_symbol;
} RELA_PATCH;

// Describes a symbol table patch
typedef struct SYMBOL_PATCH_T {
  char *original_symbol;
  char *hook_symbol;
} SYMBOL_PATCH;

typedef struct INJECTION_T {
  // Text representation of technique to show user
  char *name;
  // symbols with fixed names we need (eg. copy_to_user)
  char **required_symbols;
  size_t required_symbols_len;
  // symbols with module prefix we need (eg. lp_read)
  char **required_prefixed_symbols;
  size_t required_prefixed_symbols_len;
  // relocations we need
  RELA_STRUCT *required_prefixed_rela;
  size_t required_prefixed_rela_len;
  // relocations that are patched by name
  RELA_PATCH *hooked_rela;
  size_t hooked_rela_len;
  // relocations we need to patch by module name and suffix
  RELA_PATCH *hooked_prefixed_rela;
  size_t hooked_prefixed_rela_len;
  // symbols we need to patch (eg. _copy_to_user to copy_to_user)
  SYMBOL_PATCH *hooked_symbols;
  size_t hooked_symbols_len;
} INJECTION;

// Different methods of injection.
// They define symbol and relocation requirements,
// as well as the patches to relocation and symbol tables.
static const INJECTION injections[] = {
  // This is the default. module_llseek is hooked and _copy_to_user is used
  {
  .name = "underscore prefixes (kernel 3.x)",
  .required_symbols = (char *[]){"__register_chrdev", "_copy_to_user"},
  .required_symbols_len = 2,
  .required_prefixed_symbols = (char *[]){"_fops", "_read", "_llseek"},
  .required_prefixed_symbols_len = 3,
  .required_prefixed_rela = (RELA_STRUCT[])
    {{"_fops", "_read"}, {"_fops", "_llseek"}},
  .required_prefixed_rela_len = 2,
  .hooked_rela = (RELA_PATCH[]){{{NULL, "init_module"}, "pmem_init"},
    {{NULL, "cleanup_module"}, "pmem_cleanup"}},
  .hooked_rela_len = 2,
  .hooked_prefixed_rela = (RELA_PATCH[])
    {{{"_fops", "_read"}, "pmem_read"}, {{"_fops", "_llseek"}, "pmem_llseek"},
  // NULL means these are disabled
    {{"_fops", "_write"}, NULL}, {{"_fops", "_ioctl"}, NULL},
    {{"_fops", "_open"}, NULL}},
  .hooked_prefixed_rela_len = 5,
  .hooked_symbols = NULL,
  .hooked_symbols_len = 0
  },
  // This uses copy_to_user instead (older kernels)
  {
  .name = "no prefixes (kernel 2.6.x)",
  .required_symbols = (char *[]){"__register_chrdev", "copy_to_user"},
  .required_symbols_len = 2,
  .required_prefixed_symbols = (char *[]){"_fops", "_read", "_llseek"},
  .required_prefixed_symbols_len = 3,
  .required_prefixed_rela = (RELA_STRUCT[])
    {{"_fops", "_read"}, {"_fops", "_llseek"}},
  .required_prefixed_rela_len = 2,
  .hooked_rela = (RELA_PATCH[]){{{NULL, "init_module"}, "pmem_init"},
    {{NULL, "cleanup_module"}, "pmem_cleanup"}},
  .hooked_rela_len = 2,
  .hooked_prefixed_rela = (RELA_PATCH[])
    {{{"_fops", "_read"}, "pmem_read"}, {{"_fops", "_llseek"}, "pmem_llseek"},
  // NULL means these are disabled
    {{"_fops", "_write"}, NULL}, {{"_fops", "_ioctl"}, NULL},
    {{"_fops", "_open"}, NULL}},
  .hooked_prefixed_rela_len = 5,
  .hooked_symbols = (SYMBOL_PATCH[]){{"_copy_to_user", "copy_to_user"}},
  .hooked_symbols_len = 2
  },
  // noop_llseek is hooked and _copy_to_user is used
  {
  .name = "underscore prefixes and noop_llseek (kernel 3.x)",
  .required_symbols = (char *[]){"__register_chrdev", "_copy_to_user",
    "noop_llseek"},
  .required_symbols_len = 3,
  .required_prefixed_symbols = (char *[]){"_fops", "_read"},
  .required_prefixed_symbols_len = 2,
  .required_prefixed_rela = (RELA_STRUCT[])
    {{"_fops", "_read"}, {"_fops", "_llseek"}},
  .required_prefixed_rela_len = 2,
  .hooked_rela = (RELA_PATCH[]){{{NULL, "init_module"}, "pmem_init"},
    {{NULL, "cleanup_module"}, "pmem_cleanup"},
    {{NULL, "noop_llseek"}, "pmem_llseek"}},
  .hooked_rela_len = 3,
  .hooked_prefixed_rela = (RELA_PATCH[])
    {{{"_fops", "_read"}, "pmem_read"},
  // NULL means these are disabled
    {{"_fops", "_write"}, NULL}, {{"_fops", "_ioctl"}, NULL},
    {{"_fops", "_open"}, NULL}},
  .hooked_prefixed_rela_len = 4,
  .hooked_symbols = NULL,
  .hooked_symbols_len = 0
  },
  // This uses copy_to_user and no_llseek (older kernels)
  {
  .name = "no prefixes and no_llseek (kernel 2.6.x)",
  .required_symbols = (char *[]){"__register_chrdev", "copy_to_user",
    "no_llseek"},
  .required_symbols_len = 3,
  .required_prefixed_symbols = (char *[]){"_fops", "_read"},
  .required_prefixed_symbols_len = 2,
  .required_prefixed_rela = (RELA_STRUCT[])
    {{"_fops", "_read"}, {"_fops", "_llseek"}},
  .required_prefixed_rela_len = 2,
  .hooked_rela = (RELA_PATCH[]){{{NULL, "init_module"}, "pmem_init"},
    {{NULL, "cleanup_module"}, "pmem_cleanup"},
    {{NULL, "no_llseek"}, "pmem_llseek"}},
  .hooked_rela_len = 3,
  .hooked_prefixed_rela = (RELA_PATCH[])
    {{{"_fops", "_read"}, "pmem_read"},
  // NULL means these are disabled
    {{"_fops", "_write"}, NULL}, {{"_fops", "_ioctl"}, NULL},
    {{"_fops", "_open"}, NULL}},
  .hooked_prefixed_rela_len = 4,
  .hooked_symbols = (SYMBOL_PATCH[]){{"_copy_to_user", "copy_to_user"}},
  .hooked_symbols_len = 2
  }
  // This list can be extended when different configurations are discovered.
};

static const unsigned int SYMBUFSIZ = 128;
static const char *opt_string = "aldfvp:mh:i:o:";

// This is the embedded minpmem module
extern uint8_t MINPMEM_START;
extern uint8_t MINPMEM_END;
extern uint8_t MINPMEM_SIZE;

// This will hold the embedded driver
static ELF_OBJ parasite;
// This is a prefix string appended to sections to avoid collisions
static char *parasite_name = ".pmem";
// This is the name the module will appear as when loaded
static char *module_name = "pmem";
// And this the host module
static ELF_OBJ host_module;
// Search this path for suitable host modules
static const char *module_path = "/lib/modules/";
// This one will have the current kernel version appended
static char *specific_module_path = NULL;
// exceess to allocate for host module, defines how much data we can add
// shouldn't be too small so we can inject our host module but shouldn't be too
// large to minimize impact on target memory.
size_t excess = 1024 * 1024;
// Path to the device file we will create
static char *pmem_dev_file = "/dev/pmem";

// Get the module name from its path. Convention dictates modules filenames are
// module_name.so, so a path "/usr/lib/module.ko" results in "module".
// This function allocates memory, the caller needs to free the returned name.
char *get_module_name(const char *module_path) {
  char *module_name = NULL;
  char *name = NULL;
  char *extension = NULL;
  size_t name_len = 0;

  if ((name = (strrchr(module_path, '/') + 1)) == NULL) {
    // path might be relative and without slashes
    name = (char *)module_path;
  }
  if ((extension = strrchr(module_path, '.')) == NULL) {
    // filename might not have an extension
    extension = name + strlen(name);
  }
  name_len = extension - name;
  module_name = (char *)malloc(sizeof(char) * name_len + 1);
  strncpy(module_name, name, name_len);
  module_name[name_len] = 0x00;
  log_print(LL_DBG, "Module name is: %s", module_name);
  return module_name;
}

// Callback for ftw that determines if a file is a suitable. Be advised this
// function allocates memory to host_path, so free it when youre done.
int ftw_is_compatible_host(const char *fpath, const struct stat *sb,
    int tflag) {
  char *module_name = NULL;
  (void)sb; // We have to keep this for ftw but won't use it
  // Ignore Directories
  if (tflag != FTW_F) {
    return 0;
  }
  // Ignore non kernel module files
  if (string_has_suffix(fpath, ".ko")) {
    return 0;
  }
  if ((module_name = get_module_name(fpath)) == NULL) {
    log_print(LL_ERR, "Failed to get name for module at %s", fpath);
    return EXIT_FAILURE;
  }
  // There are multiple compatible configurations, check them all
  int module_compatible = ELF_SUCCESS;
  for (size_t i = 0; i < ARRAY_SIZE(injections); i++) {
    log_print(LL_DBG, "Testing for compatibility with profile '%s' (%d)",
        injections[i].name, i);
    if (elf_from_file(fpath, &host_module, 0) == ELF_SUCCESS) {
      // Module must contain a list of symbols
      if (host_module.symbol_exist(&host_module, injections[i].required_symbols,
            injections[i].required_symbols_len) != ELF_SUCCESS) {
        continue;
      }
      // Some of those are prefixed with it's name
      if (host_module.symbol_exist_named_suffix(&host_module, module_name,
            injections[i].required_prefixed_symbols,
            injections[i].required_prefixed_symbols_len ) != ELF_SUCCESS) {
        continue;
      }
      // Module must have relocations to specific structs
      for (size_t j = 0; j < injections[i].required_prefixed_rela_len; j++) {
        if (host_module.relocation_exist_to_sym(&host_module,
                injections[i].required_prefixed_rela[j].container,
                injections[i].required_prefixed_rela[j].symbol)
            != ELF_SUCCESS) {
          module_compatible = ELF_FAILURE;
          break;
        }
        log_print(LL_DBG, "Found rela for symbol %s into struct %s",
            injections[i].required_prefixed_rela[j].container,
            injections[i].required_prefixed_rela[j].symbol);
      }
      if (module_compatible != ELF_SUCCESS) {
        // Configuration doesn't fit, try next one
        continue;
      }
      args.host_path_len = strlen(fpath);
      args.host_path = (char *)malloc(args.host_path_len + 1);
      log_print(LL_LOG, "Found suitable host %s", fpath);
      // If we're just searching for suitable modules continue
      if (args.mode != WM_FIND) {
        memcpy(args.host_path, fpath, args.host_path_len);
        args.host_path[args.host_path_len] = 0x00;
        // Need to store which injection config we use on this module
        log_print(LL_LOG, "Using %s relocation hooking method (%d)",
                  injections[i].name, i);
        args.injection_idx = i;
        return 1;
      } else {
        // continue searching but dont bother with the other configurations,
        // we already found one that works
        break;
      }
    }
  }
  return 0;
}

void usage(char *prog_path) {
    log_print(LL_MSG, "LMAP version %d.%d: Loads an embedded memory "
        "acquisition module by finding ", LMAP_VERSION_MAJOR,
        LMAP_VERSION_MINOR);
    log_print(LL_MSG, "a suitable host and parasitizing it with an embedded "
        "minimal version of pmem.");
    log_print(LL_MSG, "(When given the -a flag it directly dumps memory to a "
        "supplied file path.)");
    log_print(LL_MSG, "usage: %s <options>", prog_path);
    log_print(LL_MSG, "\nOptions:");
    log_print(LL_MSG, "\n  mode of operation:");
    log_print(LL_MSG, "    -a dumpfile  acquire memory ");
    log_print(LL_MSG, "    -l           patch and load the acquisition module");
    log_print(LL_MSG, "    -d           "
              "dump the generated module to the filesystem");
    log_print(LL_MSG, "    -f           "
              "find suitable hosts, don't inject anything");
    log_print(LL_MSG, "\n  optional arguments:");
    log_print(LL_MSG, "    -o outfile   the output file (default: %s)",
              args.out_path);
    log_print(LL_MSG, "    -i inputfile don't inject the bundled module, "
              "use this one");
    log_print(LL_MSG, "    -h module    don't search for a suitable host module"
              ", use this one");
    log_print(LL_MSG, "    -p path      path to kernel modules");
    log_print(LL_MSG, "    -m           print the systems physical memory map");
    log_print(LL_MSG, "    -v           verbose, produces detailed debug "
              "logging\n");
}

int parse_args(int argc, char **argv) {
  int opt;

  while ((opt = getopt(argc, argv, opt_string)) != -1) {
    switch(opt) {
       case 'a':
        if (args.mode != WM_NONE) {
          usage(argv[0]);
          return EXIT_FAILURE;
        }
        args.mode = WM_ACQUIRE;
        break;

      case 'l':
        if (args.mode != WM_NONE) {
          usage(argv[0]);
          return EXIT_FAILURE;
        }
        args.mode = WM_LOAD;
        break;

      case 'd':
        if (args.mode != WM_NONE) {
          usage(argv[0]);
          return EXIT_FAILURE;
        }
        args.mode = WM_DUMP;
        break;

      case 'f':
        if (args.mode != WM_NONE) {
          usage(argv[0]);
          return EXIT_FAILURE;
        }
        args.mode = WM_FIND;
        break;

      case 'o':
        args.out_path = optarg;
        break;

      case 'p':
        args.lib_path = optarg;
        break;

      case 'i':
        args.module_path = optarg;
        break;

      case 'm':
        args.mode = WM_MMAP;
        break;

      case 'h':
        args.host_path = optarg;
        args.host_path_len = strlen(optarg);
        break;

      case 'v':
        loglevel = LL_DBG;
        break;
    }
  }
  // If we want to acquire, there should be exactly one argument left.
  if (args.mode == WM_ACQUIRE && (argc - optind != 1)) {
    usage(argv[0]);
    return EXIT_FAILURE;
  } else {
    // the last remaining argument is the name of the dumpfile.
    args.acquisition_path = argv[optind];
  }
  // This can be dangerous, we want the user to explicitly tell us what to do
  if (args.mode == WM_NONE) {
    usage(argv[0]);
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}

size_t get_filesize(char *path) {
  struct stat st;

  if (stat(path, &st) < 0) {
    perror("[-] Can't open input file: ");
    return 0;
  }
  return st.st_size;
}

int init_elf_objs(void) {
  if (args.module_path == NULL) {
    args.module_size = (size_t)&MINPMEM_SIZE;
    log_print(LL_DBG, "loading internal parasite of size %d",
        &MINPMEM_SIZE);
    if (elf_from_mem(&MINPMEM_START,
          (size_t)&MINPMEM_SIZE, &parasite, 0) != ELF_SUCCESS) {
      log_print(LL_ERR, "Embedded minpem corrupted, exiting...");
      return EXIT_FAILURE;
    }
  } else {
    args.module_size = get_filesize(args.module_path);
    if (elf_from_file(args.module_path, &parasite, 0) != ELF_SUCCESS) {
      log_print(LL_ERR, "Failed to load parasite from file %s",
          args.module_path);
      return EXIT_FAILURE;
    }
  }
  return EXIT_SUCCESS;
}

// Walk the filesystem starting from search_path and put the path of a kernel
// module into host that is suited for infection by the minpmem module.
int find_compatible_host(void) {
  struct utsname utsbuf;

  if (args.lib_path == NULL) {
    if (uname(&utsbuf)) {
      log_print(LL_ERR, "Can't determine kernel version, searching for modules"
          "can't work reliably");
      return EXIT_FAILURE;
    } else {
      log_print(LL_DBG, "Kernel version is '%s'", utsbuf.release);
    }
    specific_module_path = (char *)malloc(strlen(module_path) +
        strlen(utsbuf.release));
    strcpy(specific_module_path, module_path);
    strcat(specific_module_path, utsbuf.release);
  } else {
    // manual lib/modules path specified
    specific_module_path = args.lib_path;
  }
  log_print(LL_LOG, "Scanning modules in %s for suitable host",
      specific_module_path);
  if (ftw(specific_module_path, ftw_is_compatible_host, 20) == 0 &&
      args.mode != WM_FIND) {
    log_print(LL_ERR, "No suitable host modules found");
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}

int hook_prefixed_rela(char *mod_name) {
  char mod_symbol_name[SYMBUFSIZ];
  size_t mod_len = strlen(mod_name);
  char *rela_sym;
  size_t rela_sym_len;
  RELA_PATCH *patches = injections[args.injection_idx].hooked_prefixed_rela;
  size_t patches_len = injections[args.injection_idx].hooked_prefixed_rela_len;

  for (size_t i = 0; i < patches_len; i++) {
    rela_sym = patches[i].target_rela.symbol;
    rela_sym_len = strlen(rela_sym);
    // Check if the buffer will fit the prefixed symbol name
    if (rela_sym_len + mod_len + 1 >= SYMBUFSIZ) {
      log_print(LL_ERR, "Can't hook relocation for rela in %s, "
          "length exceeds buffer size", rela_sym);
        return EXIT_FAILURE;
    }
    // Prefix symbols with module and parasite names
    strncpy(mod_symbol_name, mod_name, mod_len + 1);
    strncat(mod_symbol_name, rela_sym, rela_sym_len + 1);
    if (elf_hook_all_relocations(&host_module, mod_symbol_name,
          patches[i].hook_symbol, 0) != ELF_SUCCESS) {
      log_print(LL_ERR, "Failed to hook relocations in %s for %s",
          mod_symbol_name, patches[i].hook_symbol);
      if (patches[i].hook_symbol == NULL) {
        log_print(LL_LOG, "This is non critical, we just try to disable "
            "every possible file operation we don't use for stability reasons");
      } else {
        return EXIT_FAILURE;
      }
    }
  }
  return EXIT_SUCCESS;
}

int hook_relocations(void) {
  RELA_PATCH *rela = injections[args.injection_idx].hooked_rela;
  size_t rela_len = injections[args.injection_idx].hooked_rela_len;

  for (size_t i = 0; i < rela_len; i++) {
    if (elf_hook_all_relocations(&host_module, rela[i].target_rela.symbol,
        rela[i].hook_symbol, 0) != EXIT_SUCCESS) {
      log_print(LL_ERR, "Failed to hook relocation from %s to %s",
          rela[i].target_rela.symbol, rela[i].hook_symbol);
      if (rela[i].hook_symbol == NULL) {
        log_print(LL_LOG, "This is non critical, we just try to disable "
            "every possible file operation we don't use for stability reasons");
      } else {
        return EXIT_FAILURE;
      }
    }
  }
  return EXIT_SUCCESS;
}

// Initialize an ELF header with default values for a core dump file
// and a specific number of program headers.
//
// args: header is a pointer to the mach_header_64 struct to initialize.
//       num_segments is the number of program headers to add to this header.
//
void prepare_elf_header(Elf_Ehdr *header, unsigned int num_segments) {
  // All values that are unset will be zero
  bzero(header, sizeof(Elf_Ehdr));
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
  header->e_phoff    = sizeof(Elf_Ehdr);
  header->e_ehsize   = sizeof(Elf_Ehdr);
  header->e_phentsize= sizeof(Elf_Phdr);
  header->e_phnum    = num_segments;
  header->e_shentsize= sizeof(Elf_Shdr);
}

// Initialize an ELF program header with data from an EFI segment descriptor.
//
// args: program_header is a pointer to an Elf_Phdr struct to initialize.
//       segment is a pointer to the EFI segment descriptor to copy data from.
//       file_offset is the raw offset into the mach-o file the segment will be
//       actually stored in.
//
void prepare_elf_program_header(Elf_Phdr *program_header, MEMORY_RANGE *range,
    uint64_t file_offset) {
  // All values that are unset will be zero
  bzero(program_header, sizeof(Elf_Phdr));
  program_header->p_type = PT_LOAD;
  program_header->p_paddr = range->start;
  program_header->p_memsz = range->pages * PAGE_SIZE;
  program_header->p_align = PAGE_SIZE;
  program_header->p_flags = PF_R;
  program_header->p_offset = file_offset;
  program_header->p_filesz = range->pages * PAGE_SIZE;
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
    log_print(LL_ERR, "Could not seek to beginning of file");
    return EXIT_FAILURE;
  }
  if (write(file, header, header_size) != header_size) {
    log_print(LL_ERR, "Failed to write header");
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
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
unsigned int write_segment(MEMORY_RANGE *segment, int mem_dev, int dump_file,
    size_t file_offset) {
  size_t segment_size = segment->pages * PAGE_SIZE;
  size_t page = segment->start;
  size_t end = segment->start + segment_size;
  uint8_t page_buf[PAGE_SIZE];

  // Dump contiguous segments one page at a time
  while (page < end) {
    if (lseek(mem_dev, page, SEEK_SET) < 0) {
      log_print(LL_ERR, "Could not seek to page in memory device");
      return EXIT_FAILURE;
    }
    if (read(mem_dev, page_buf, PAGE_SIZE) != PAGE_SIZE) {
      log_print(LL_ERR, "Failed to read page");
      return EXIT_FAILURE;
    }
    // Copy the page to the indicated offset in the mach-o file
    if (lseek(dump_file, file_offset, SEEK_SET) < 0) {
      log_print(LL_ERR, "Could not seek to segment in dump file");
      return EXIT_FAILURE;
    }
    if (write(dump_file, page_buf, PAGE_SIZE) != PAGE_SIZE) {
      log_print(LL_ERR, "Failed to write page");
      return EXIT_FAILURE;
   }
    // Advance the read and write pointers
    page += PAGE_SIZE;
    file_offset += PAGE_SIZE;
  }
  return EXIT_SUCCESS;
}


// Parse the mmap and dump each section into an elf core dump file.
// Memory holes are ignored and unreadable sections like MMIO are written as
// empty segments. For each segment a program header is created in the elf
// file, that documents the physical address range it occupied.
//
// args:
//       mm is a pointer to a memory map of the system
//       mem_dev is an open filehandle to the pmem device file (/dev/pmem).
//       dump_file is an open filehandle to which the image will be written.
//
// return: EXIT_SUCCESS or EXIT_FAILURE.
//
unsigned int dump_memory_elf(MEMORY_MAP *mm, int mem_dev, int dump_file) {
  unsigned int status = EXIT_FAILURE;
  MEMORY_RANGE *curr_range = NULL;
  size_t curr_idx = 0;
  uint64_t file_offset = 0;
  uint64_t phys_as_size = 0;
  uint64_t bytes_imaged = 0;
  unsigned int headers_bufsize = 0;
  uint8_t *elf_headers_buf = NULL;
  Elf_Ehdr *elf_header = NULL;
  Elf_Phdr *program_header = NULL;

  // Prepare an elf phdr for each memory range and 1 ehdr for the file
  headers_bufsize = (
      sizeof(Elf_Ehdr) + mm->size * sizeof(Elf_Phdr));
  if ((elf_headers_buf = (uint8_t *)malloc(headers_bufsize)) == NULL) {
    log_print(LL_ERR, "Could not allocate memory for mach-o headers");
    goto error_headers;
  }
  // The ELF header is at the beginning of the buffer
  elf_header = (Elf_Ehdr *)elf_headers_buf;
  // The program headers come right after the elf header
  program_header = (Elf_Phdr *)(elf_headers_buf + sizeof(Elf_Ehdr));
  prepare_elf_header(elf_header, mm->size);
  // Data will be written right after the header and load commands
  file_offset = headers_bufsize;
  log_print(LL_LOG, "Starting to dump memory");
  // Iterate over each section in the physical memory map and write it to disk.
  for (curr_idx = 0; curr_idx < mm->size; curr_idx++) {
    if (memory_map_get(mm, curr_idx, &curr_range) != ELF_SUCCESS) {
      log_print(LL_ERR, "Memory map corrupted, unable to write memory dump");
      return status;
    }
    uint64_t segment_size = curr_range->pages * PAGE_SIZE;
    prepare_elf_program_header(program_header, curr_range, file_offset);
    log_print(LL_NNL, "[%016llx - %016llx] ", curr_range->start,
        curr_range->start + segment_size - 1);
    if (write_segment(curr_range, mem_dev, dump_file, file_offset)
        == EXIT_FAILURE) {
      log_print(LL_ERR, "Failed to dump segment %d\n", curr_idx);
      goto error;
    }
    file_offset += segment_size;
    bytes_imaged += segment_size;
    log_print(LL_MSG, "[WRITTEN]");
    program_header++;
    // Calculate statistics
    uint64_t end_addr = curr_range->start + curr_range->pages * PAGE_SIZE;
    if (end_addr > phys_as_size) {
      phys_as_size = end_addr;
    }
  }
  write_header(dump_file, elf_headers_buf, headers_bufsize);
  log_print(LL_LOG, "Acquired %lld pages (%lld bytes)",
            bytes_imaged / PAGE_SIZE, bytes_imaged);
  log_print(LL_LOG, "Size of accessible physical address space: %lld bytes "
      "(%lld segments)", phys_as_size, curr_idx);
  status = EXIT_SUCCESS;
error:
  free(elf_headers_buf);
error_headers:
  return status;
}


// Will read the memory runs specified in mm from the device file and
// write an ELF memory dump into the output file.
ELF_ERROR acquire_memory(char *in_path, char *out_path) {
  ELF_ERROR status = ELF_FAILURE;
  MEMORY_MAP mm;
  int pmem_major;
  int mem_dev = -1;
  int dump_file = -1;

  if (memory_map_init(&mm) != ELF_SUCCESS) {
    log_print(LL_ERR, "Can't init memory map data structures");
    return EXIT_FAILURE;
  }
  if (get_physical_memory_map(&mm) != ELF_SUCCESS) {
    log_print(LL_ERR, "Can't get map of physical memory");
    goto error_mmap;
  }
  if (load_module(&host_module) != EXIT_SUCCESS) {
    log_print(LL_ERR, "Unable to load memory driver, aborting");
    goto error_insmod;
  }
  if (pmem_get_major(&pmem_major) != EXIT_SUCCESS) {
    log_print(LL_ERR, "Can't get pmem drivers major number");
    goto error_insmod;
  }
  if (pmem_mknod(pmem_dev_file, pmem_major) != EXIT_SUCCESS) {
    log_print(LL_ERR, "Unable to create /dev device file (mknod failed)");
    goto error_mknod;
  }
  if ((mem_dev = open(in_path, O_RDONLY)) == -1) {
    log_print(LL_ERR, "Error opening physical memory device");
    goto error_memdev;
  }
  if ((dump_file =
       open(out_path, O_RDWR | O_CREAT | O_TRUNC, 0440)) == -1) {
    log_print(LL_ERR, "Error opening dump file");
    goto error_dumpfile;
  }
  if (dump_memory_elf(&mm, mem_dev, dump_file)) {
    log_print(LL_ERR, "Error dumping elf image of memory\n");
    goto error;
  }
  log_print(LL_LOG, "Successfully wrote elf image of memory to %s\n",
            out_path);
  status = EXIT_SUCCESS;
error:
  close(dump_file);
error_dumpfile:
  close(mem_dev);
error_memdev:
  if (pmem_rmnod(pmem_dev_file) != EXIT_SUCCESS) {
    log_print(LL_ERR, "Failed to remove pmem device file in /dev");
    status = EXIT_FAILURE;
  }
error_mknod:
  if (unload_module(args.host_name) == EXIT_FAILURE) {
    log_print(LL_ERR, "Failed to unload pmem kernel module");
    status = EXIT_FAILURE;
  }
error_insmod:
  memory_map_free(&mm);
error_mmap:
  return status;
}

int print_memory_map(void) {
  MEMORY_MAP mm;

  if (memory_map_init(&mm) != ELF_SUCCESS) {
    log_print(LL_ERR, "Can't init memory map data structures");
    return EXIT_FAILURE;
  }
  if (get_physical_memory_map(&mm) != ELF_SUCCESS) {
    log_print(LL_ERR, "Can't get map of physical memory");
    return EXIT_FAILURE;
  }
  memory_map_print(&mm);
  return EXIT_SUCCESS;
}

int main (int argc, char **argv) {
  if (parse_args(argc, argv) != EXIT_SUCCESS) {
    return EXIT_FAILURE;
  }
  // Some modes don't require to create a parasited module,
  // we'll deal with that here
  switch (args.mode) {
    case WM_MMAP:
      return print_memory_map();

    case WM_FIND:
      find_compatible_host();
      return EXIT_SUCCESS;

    default:
      // All other modes are handled at the end when we finish finding and
      // injecting a module...
      break;
  }
  // Only search for a target if the user didn't supply one manually
  if (args.host_path == NULL) {
    if (find_compatible_host() != EXIT_SUCCESS) {
      log_print(LL_ERR, "Can't continue without host, aborting");
      return EXIT_FAILURE;
    }
  } else {
    // If the user supplied a target we still have to check if it's compatible
    if (ftw_is_compatible_host(args.host_path, NULL, FTW_F) != 1) {
      log_print(LL_ERR, "module %s is incompatible, aborting...",
                args.host_path);
      return EXIT_FAILURE;
    } else {
      log_print(LL_LOG, "Using injection method %s (%d)",
          injections[args.injection_idx].name, args.injection_idx);
    }
  }
  if (init_elf_objs() != EXIT_SUCCESS) {
    return EXIT_FAILURE;
  }
  if (elf_from_file(args.host_path, &host_module, excess)) {
    log_print(LL_ERR, "Can't read host module %s, aborting...", args.host_path);
    return EXIT_FAILURE;
  }
  if (elf_inject_obj(&host_module, &parasite, parasite_name) != ELF_SUCCESS) {
    log_print(LL_ERR, "Can't inject parasite into host %s", args.host_path);
    return EXIT_FAILURE;
  } else {
    log_print(LL_LOG, "Successfully injected parasite into %s", args.host_path);
  }
  if (hook_relocations() != EXIT_SUCCESS) {
    return EXIT_FAILURE;
  }
  args.host_name = get_module_name(args.host_path);
  if (hook_prefixed_rela(args.host_name) != ELF_SUCCESS) {
    log_print(LL_ERR, "Failed to hook necessary symbol relocations to redirect"
        "file operations");
    return EXIT_FAILURE;
  }
  log_print(LL_DBG, "Successfully hooked all necessary relocations");
  if (elf_clean_dependencies(&host_module) != ELF_SUCCESS) {
    log_print(LL_ERR, "Could not remove module dependencies, refusing to load");
    return EXIT_FAILURE;
  }
  if (elf_rename_module(&host_module, args.host_name, module_name)
      != ELF_SUCCESS) {
    log_print(LL_ERR, "Could not rename host module %s to %s, "
        "loading could fail due to the original still being loaded.\n"
        "If it fails try removing it first with 'rmmod %s'",
        args.host_name, module_name, args.host_name);
    // We don't fail here as it might still work.
    // Worst case is module won't load due to host already being loaded.
  }
  log_print(LL_DBG, "Sucessfully removed all module dependencies");
  switch (args.mode) {
    case WM_ACQUIRE:
      if (acquire_memory(pmem_dev_file, args.acquisition_path) != ELF_SUCCESS) {
          log_print(LL_ERR, "Memory acquisition failed");
          return EXIT_FAILURE;
      }
      break;

    case WM_LOAD:
      if (load_module(&host_module) != EXIT_SUCCESS) {
        log_print(LL_ERR, "Failed to load pmem kernel module");
        return EXIT_FAILURE;
      }
      break;

    case WM_DUMP:
      if (elf_to_file(args.out_path, &host_module) == ELF_SUCCESS) {
        log_print(LL_LOG, "Dumped parasitized module to %s", args.out_path);
      } else {
        log_print(LL_ERR, "Failed to dump module to %s", args.out_path);
        return EXIT_FAILURE;
      }
      return EXIT_SUCCESS;

    default:
      log_print(LL_ERR, "Invalid commandline");
      usage(argv[0]);
      return EXIT_FAILURE;
  }
}
