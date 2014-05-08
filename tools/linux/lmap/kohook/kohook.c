// Commandline interface to elfrelink. Can be used to hook symbols by rewriting
// symbol table entries or relocation entries.
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
#include <fcntl.h>
#include <getopt.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>

#include "../elfrelink/elf_generic.h"
#include "../elfrelink/elf_object.h"
#include "../elfrelink/elfrelink.h"
#include "kohook.h"
#include "../log/log.h"

static const char *opt_string = "ftrR:o:s:h:T:o:c";

void usage(char *prog_path) {
    log_print(LL_MSG, "Relinks ELF64 files by manipulating the symbol "
            "or relocation table.");
    log_print(LL_MSG, "This only works on relocateable object files "
            "such as kernel modules.");
    log_print(LL_MSG, "usage: %s <options> [FILE]", prog_path);
    log_print(LL_MSG, "\nOptions:");
    log_print(LL_MSG, "\n  mode of operation:");
    log_print(LL_MSG, "    -t          hook symbol by changing it's offset in "
        "the symbol table (default)");
    log_print(LL_MSG, "    -r          hook symbol based relocation table entry"
        " by changing the symbol index in each relocation entry");
    log_print(LL_MSG, "    -f          find relocations of symbol into other "
        "symbol");
    log_print(LL_MSG, "    -c          clean module dependencies");
    log_print(LL_MSG, "\n  mandatory options:");
    log_print(LL_MSG, "    -s symbol   the symbol to hook");
    log_print(LL_MSG, "\n  optional:");
    log_print(LL_MSG, "    -h hook     the hook function (if not provided any "
        "relocations found will be deleted)");
    log_print(LL_MSG, "    -o outfile  the output file (default: hooked.ko)");
    log_print(LL_MSG, "    -T target   will also overwrite the target offset "
        "(essentially hijacks an entry)");
    log_print(LL_MSG, "    -R symbol   relocated symbol '-f' searches for ");
    log_print(LL_MSG, "\nExamples:");
    log_print(LL_MSG, "    %s -t -s init_module -h init_hook module.ko",
      prog_path);
    log_print(LL_MSG, "    %s -r -s init_module -h init_hook module.ko",
      prog_path);
}

int main (int argc, char **argv) {
  int opt;
  ELF_OBJ obj;
  ARGS args = {
    .out_path = NULL,
    .symbol = NULL,
    .hook = NULL,
    .relocation = NULL,
    .section = NULL,
    .offset = 0,
    .target_offset = 0,
    .mode = HM_NONE
  };

  while ((opt = getopt(argc, argv, opt_string)) != -1) {
    if (optind == argc) {
      log_print(LL_ERR, "You must provide an input file!\n");
      usage(argv[0]);
      return EXIT_FAILURE;
    }
    switch(opt) {
      case 'c':
        if (args.mode != HM_NONE) {
          usage(argv[0]);
          return EXIT_FAILURE;
        }
        args.mode = HM_CLEAN;
        break;

      case 't':
        if (args.mode != HM_NONE) {
          usage(argv[0]);
          return EXIT_FAILURE;
        }
        args.mode = HM_SYMTAB;
        break;
      case 'r':
        if (args.mode != HM_NONE) {
          usage(argv[0]);
          return EXIT_FAILURE;
        }
        args.mode = HM_RELA;
        break;
      case 'f':
        if (args.mode != HM_NONE) {
          usage(argv[0]);
          return EXIT_FAILURE;
        }
        args.mode = HM_RELA_FIND;
        break;
      case 'o':
        args.out_path = optarg;
        break;
      case 's':
        args.symbol = optarg;
        break;
      case 'h':
        args.hook = optarg;
        break;
      case 'T':
        args.target_offset = strtoul(optarg, NULL, 16);
        break;
      case 'R':
        args.relocation = optarg;
        break;
    }
  }
  // First check if args are correct
  switch (args.mode) {
    case HM_RELA_FIND:
      if (!args.relocation) {
        log_print(LL_ERR, "Must provide a symbol to search relocations for");
        return EXIT_FAILURE;
      }
      // Next check also applies, so fall through
    case HM_SYMTAB:
    case HM_RELA:
      if (!args.symbol) {
        log_print(LL_ERR, "Must provide a symbol to hook");
        return EXIT_FAILURE;
      }
      break;
    case HM_CLEAN:
      break; // No args needed
    default:
      log_print(LL_ERR, "Invalid mode of operation");
      usage(argv[0]);
      return EXIT_FAILURE;
  }
  // Last arg has to be the input file
  if (elf_from_file(argv[argc-1], &obj, 0) != ELF_SUCCESS) {
    log_print(LL_ERR, "Couldn't parse input file, aborting");
    return EXIT_FAILURE;
  }
  switch (args.mode) {
    case HM_SYMTAB:
      if (elf_hook_symbol(&obj, args.symbol, args.hook) != EXIT_SUCCESS) {
        log_print(LL_ERR, "Failed to hook symbol %s with hook symbol %s, "
            "aborting", args.symbol, args.hook);
        return EXIT_FAILURE;
      }
      break;

    case HM_RELA:
      if (elf_hook_all_relocations(&obj, args.symbol, args.hook,
            args.target_offset) != EXIT_SUCCESS) {
        log_print(LL_ERR, "Failed to hook symbol %s with hook symbol %s, "
            "aborting", args.symbol, args.hook);
        return EXIT_FAILURE;
      }
      break;

    case HM_RELA_FIND:
      if (obj.relocation_exist_to_sym(&obj, args.symbol, args.relocation)) {
        log_print(LL_ERR, "No relocations of %s to %s found in %s",
          args.symbol, args.relocation, argv[argc - 1]);
      }
      return EXIT_SUCCESS;
      break;

    case HM_CLEAN:
      if (elf_clean_dependencies(&obj)) {
        log_print(LL_ERR, "Failed to clean dependencies");
        return EXIT_FAILURE;
      }
      log_print(LL_LOG, "Cleaned dependencies from module");
      break;

    default:
      return EXIT_FAILURE;
  }
  // If the -o flag wasn't set write the changes directly to the input
  if (!args.out_path) {
    args.out_path = argv[argc-1];
  }
  if (elf_to_file(args.out_path, &obj)) {
    log_print(LL_ERR, "Couldn't write outfile, discarding patches");
    return EXIT_FAILURE;
  }
  log_print(LL_LOG, "Patches written to file %s", args.out_path);
  elf_free_obj(&obj);

  return EXIT_SUCCESS;
}
