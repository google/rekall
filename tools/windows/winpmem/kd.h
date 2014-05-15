/*
   Copyright 2012 Michael Cohen <scudette@gmail.com>

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

#ifndef _WINPMEM_KD_H
#define _WINPMEM_KD_H

#include "winpmem.h"
#include "ntimage.h"

IMAGE_DOS_HEADER *KernelGetModuleBaseByPtr(IN void *in_section,
					   IN void *exported_name);

void *KernelGetProcAddress(void *image_base, char *func_name);

int GetKPCR(struct PmemMemoryInfo *info);

#endif // _WINPMEM_KD_H
