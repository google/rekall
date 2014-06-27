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

#ifndef _REKALL_TOOL_ELF_LKM_CONTROL_H_
#define _REKALL_TOOL_ELF_LKM_CONTROL_H_

#include "../elfrelink/elf_object.h"

// Parses the kernel debug buffer and finds pmems major number
int pmem_get_major(int *major);
// Creates a device file with a drivers major number and minor 0
int pmem_mknod(char *path, int major);
// Removes a device file from the file system
int pmem_rmnod(char *path);
// Calls delete_module to remove a module from the kernel
int unload_module(char *name);
// Calls init_module to load a module into the kernel
int load_module(ELF_OBJ *module, char *name);

#endif // _REKALL_TOOL_ELF_LKM_CONTROL_H_
