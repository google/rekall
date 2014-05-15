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

#include "kd.h"

/*
  This code inspired and updated from
  http://alter.org.ua/docs/nt_kernel/procaddr/#KernelGetModuleBaseByPtr

  We try to locate the kernel's base address. We do this by looking for an MZ
  header a short space before the location of a known exported symbol.

  Unfortunately we might hit unmapped kernel memory which will blue screen so we
  need to check if the kernel address is at all valid.
*/

IMAGE_DOS_HEADER *KernelGetModuleBaseByPtr(IN void *in_section,
					   IN void *exported_name) {
  unsigned char *p;
  IMAGE_DOS_HEADER *dos;
  IMAGE_NT_HEADERS *nt;
  int count = 0;

  p = (unsigned char *)((uintptr_t)in_section & ~(PAGE_SIZE-1));

  for(;p;p -= PAGE_SIZE) {
    count ++;

    // Dont go back too far.
    if (count > 0x800) {
      return NULL;
    };

    __try {
      dos = (IMAGE_DOS_HEADER *)p;

      // If this address is not mapped in, there will be a BSOD
      // PAGE_FAULT_IN_NONPAGED_AREA so we check first.
      if(!MmIsAddressValid(dos)) {
        continue;
      }

      if(dos->e_magic != 0x5a4d) // MZ
        continue;

      nt = (IMAGE_NT_HEADERS *)((uintptr_t)dos + dos->e_lfanew);
      if((uintptr_t)nt >= (uintptr_t)in_section)
        continue;

      if((uintptr_t)nt <= (uintptr_t)dos)
        continue;

      if(!MmIsAddressValid(nt)) {
        continue;
      }
      if(nt->Signature != 0x00004550) // PE
        continue;

      break;

      // Ignore potential errors.
    } __except(EXCEPTION_CONTINUE_EXECUTION) {}
  }

  return dos;
}

/* Resolve a kernel function by name.
 */
void *KernelGetProcAddress(void *image_base, char *func_name) {
  void *func_address = NULL;

  __try  {
    int size = 0;
    IMAGE_DOS_HEADER *dos =(IMAGE_DOS_HEADER *)image_base;
    IMAGE_NT_HEADERS *nt  =(IMAGE_NT_HEADERS *)((uintptr_t)image_base + dos->e_lfanew);

    IMAGE_DATA_DIRECTORY *expdir = (IMAGE_DATA_DIRECTORY *)
      (nt->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_EXPORT);

    IMAGE_EXPORT_DIRECTORY *exports =(PIMAGE_EXPORT_DIRECTORY)
      ((uintptr_t)image_base + expdir->VirtualAddress);

    uintptr_t addr = (uintptr_t)exports-(uintptr_t)image_base;

    // These are arrays of RVA addresses.
    unsigned int *functions = (unsigned int *)((uintptr_t)image_base +
                                               exports->AddressOfFunctions);

    unsigned int *names = (unsigned int *)((uintptr_t)image_base +
                                           exports->AddressOfNames);

    short *ordinals = (short *)((uintptr_t)image_base +
                                exports->AddressOfNameOrdinals);

    unsigned int max_name  = exports->NumberOfNames;
    unsigned int  max_func  = exports->NumberOfFunctions;

    unsigned int i;

    for (i = 0; i < max_name; i++) {
      unsigned int ord = ordinals[i];
      if(i >= max_name || ord >= max_func) {
        return NULL;
      }

      if (functions[ord] < addr || functions[ord] >= addr + size) {
        if (strcmp((char *)image_base + names[i], func_name)  == 0) {
          func_address = (char *)image_base + functions[ord];
          break;
        }
      }
    }
  }
  __except(EXCEPTION_EXECUTE_HANDLER) {
    func_address = NULL;
  }

  return func_address;
} // end KernelGetProcAddress()


/* Search for a section by name.

   Returns the mapped virtual memory section or NULL if not found.
*/
IMAGE_SECTION_HEADER *GetSection(IMAGE_DOS_HEADER *image_base, char *name) {
  IMAGE_NT_HEADERS *nt  = (IMAGE_NT_HEADERS *)
    ((uintptr_t)image_base + image_base->e_lfanew);
  int i;
  int number_of_sections = nt->FileHeader.NumberOfSections;

  IMAGE_SECTION_HEADER *sections = (IMAGE_SECTION_HEADER *)
    ((uintptr_t)&nt->OptionalHeader + nt->FileHeader.SizeOfOptionalHeader);

  for (i=0; i<number_of_sections; i++) {
    if(!strcmp(sections[i].Name, name))
      return &sections[i];
  };

  return NULL;
};


/*
  Enumerate the KPCR blocks from all CPUs.
*/

int GetKPCR(struct PmemMemoryInfo *info) {
  __int64 active_processors = KeQueryActiveProcessors();
  int i;

  for (i=0; i < 32; i++) {
    info->KPCR[i].QuadPart = 0;
  };

  for (i=0; i < 32; i++) {
    if (active_processors & ((__int64)1 << i)) {
      KeSetSystemAffinityThread((__int64)1 << i);
#if _WIN64 || __amd64__
      //64 bit uses gs and _KPCR.Self is at 0x18:
      info->KPCR[i].QuadPart = (uintptr_t)__readgsqword(0x18);
#else
      //32 bit uses fs and _KPCR.SelfPcr is at 0x1c:
      info->KPCR[i].QuadPart = (uintptr_t)__readfsword(0x1c);
#endif
    };
  };

  KeRevertToUserAffinityThread();

  return 1;
};
