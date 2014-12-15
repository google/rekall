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

#ifndef _REKALL_TOOL_ELF_KCORE_H_
#define _REKALL_TOOL_ELF_KCORE_H_

#include "memory_map.h"

const char *kcore_path;
const uint64_t kcore_pmem_min;
const uint64_t kcore_pmem_max;

// Parses /proc/kcore and creates a map of all physical RAM ranges
ELF_ERROR get_memory_map_kcore(MEMORY_MAP *mm);
// Dumps all physical memory to a file by reading from /proc/kcore
ELF_ERROR acquire_memory_kcore(const char *dump_path);

#endif // _REKALL_TOOL_ELF_KCORE_H_
