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

#ifndef _REKALL_TOOL_KOHOOK_H_
#define _REKALL_TOOL_KOHOOK_H_

#include "../elfrelink/elf_generic.h"

typedef enum HOOKMODE_T {
  HM_NONE,
  HM_CLEAN,
  HM_REL,
  HM_RELA,
  HM_RELA_FIND,
  HM_SYMTAB
} HOOKMODE;

typedef struct ARGS_T {
  char *out_path;
  char *in_path;
  char *symbol;
  char *hook;
  char *relocation;
  char *section;
  Elf_Word offset;
  Elf_Word target_offset;
  HOOKMODE mode;
} ARGS;

#endif  // _REKALL_TOOL_KOHOOK_H_
