// Linux specific implementation of the pte_mmap module.
//
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
//

#ifndef _VOLATILITY_DRIVER_PTE_MMAP_LINUX_H_
#define _VOLATILITY_DRIVER_PTE_MMAP_LINUX_H_

#ifndef __linux
  #error "This module is linux specific. Use the pte_mmap subclass for your OS"
#endif
#ifndef __LP64__
  #error "This module contains x86-64 code and cannot run on your machine"
#endif

#include "pte_mmap.h"

#include <linux/module.h>

// Initializer that fills an operating system specific vtable,
// allocates memory, etc.
PTE_MMAP_OBJ *pte_mmap_linux_new(void);

// Call this before freeing obj or the rogue_page.
// Will reset the page table entry for the rogue page.
void pte_mmap_linux_delete(PTE_MMAP_OBJ *self);

#endif  // _VOLATILITY_DRIVER_PTE_MMAP_LINUX_H_
