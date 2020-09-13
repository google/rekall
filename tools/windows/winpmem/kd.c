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
#include "SystemModInfoInvocation.h"

// xxx: returns nt module base address as variatic hex number (SIZE_T) 
// 		(aka a ZwQuerySystemInformation invocation nr. XI)
//      The perfect routine for PASSIVE_LEVEL drivers; perfectly safe and no heuristic.
SIZE_T KernelGetModuleBaseByPtr()
{
	NTSTATUS status = STATUS_SUCCESS;
	
	ULONG ModuleCount = 0;
	ULONG i = 0, j=0;
	
	ULONG NeedSize = 0;
	ULONG preAllocateSize = 0x1000;
	PVOID pBuffer = NULL;
	
	SIZE_T imagebase_of_nt = 0;
	
	PSYSTEM_MODULE_INFORMATION pSystemModuleInformation;
	
	PAGED_CODE();

	// Preallocate 0x1000 bytes and try.
	pBuffer = ExAllocatePoolWithTag( NonPagedPool, preAllocateSize, PMEM_POOL_TAG );
	if( pBuffer == NULL )
	{
		return 0;
	}
   
	status = ZwQuerySystemInformation( SystemModuleInformation, pBuffer, preAllocateSize, &NeedSize );
  
	if (( status == STATUS_INFO_LENGTH_MISMATCH ) || (status == STATUS_BUFFER_OVERFLOW))
	{
		ExFreePool( pBuffer );
		pBuffer = ExAllocatePoolWithTag( NonPagedPool, NeedSize , PMEM_POOL_TAG );
		status = ZwQuerySystemInformation( SystemModuleInformation, pBuffer, NeedSize, &NeedSize );
	}
   
	if( !NT_SUCCESS(status) )
	{
		ExFreePool( pBuffer );
		DbgPrint("KernelGetModuleBaseByPtr() failed with %08x.\n",status);
		return 0;    
	}

	pSystemModuleInformation = (PSYSTEM_MODULE_INFORMATION)pBuffer;

	ModuleCount = pSystemModuleInformation->Count;

	for( i = 0; i < ModuleCount; i++ )
	{
		if (pSystemModuleInformation->Module[i].ImageName)
		{
			for (j=0;j<250;j++)
			{
				if (((pSystemModuleInformation->Module[i].ImageName[j+0] | 0x20) == 'n') &&
					((pSystemModuleInformation->Module[i].ImageName[j+1] | 0x20) == 't') &&
					((pSystemModuleInformation->Module[i].ImageName[j+2] | 0x20) == 'o') &&
					((pSystemModuleInformation->Module[i].ImageName[j+3] | 0x20) == 's'))
					{
						imagebase_of_nt = (SIZE_T) pSystemModuleInformation->Module[i].Base;
						return imagebase_of_nt;
					}
					
			}	
		}
	}

	ExFreePool(pBuffer);
	return 0;
}


// xxx: get proc address for kernel space
// could support irql > 0.
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
   could support irql > 0.
*/
IMAGE_SECTION_HEADER* GetSection(IMAGE_DOS_HEADER *image_base, char *name) 
{
  IMAGE_NT_HEADERS *nt  = (IMAGE_NT_HEADERS *)
    ((uintptr_t)image_base + image_base->e_lfanew);
  int i;
  int number_of_sections = nt->FileHeader.NumberOfSections;

  IMAGE_SECTION_HEADER *sections = (IMAGE_SECTION_HEADER *)
    ((uintptr_t)&nt->OptionalHeader + nt->FileHeader.SizeOfOptionalHeader);

  for (i=0; i<number_of_sections; i++) {
    if(!strcmp((char *)sections[i].Name, name))
      return &sections[i];
  };

  return NULL;
};


/*
  Enumerate the KPCR blocks from all CPUs.
*/

void GetKPCR(struct PmemMemoryInfo *info) 
{
	// a bitmask of the currently active processors
	unsigned __int64 active_processors = KeQueryActiveProcessors();
	unsigned __int64 i=0;
	#if defined(_WIN64)
	unsigned __int64 maxProcessors=64; // xxx: 64 processors possible on 64 bit os
	#else
	unsigned __int64 maxProcessors=32;  // but only 32 on 32 bit, meaning that only half so much KPCR slots.
	#endif
	SIZE_T one = 1; // xxx: for correct bitshifting depending on runtime OS bitness.
  
	PAGED_CODE();
	
	RtlZeroMemory(info->KPCR, sizeof(info->KPCR) );

	for (i=0; i<maxProcessors; i++) 
	{
		if (active_processors & (one << i)) 
		{
		  KeSetSystemAffinityThread(one << i);
		#if _WIN64
			  //64 bit uses gs and _KPCR.Self is at 0x18:
			  info->KPCR[i].QuadPart = (uintptr_t)__readgsqword(0x18);
		#else
			  //32 bit uses fs and _KPCR.SelfPcr is at 0x1c:
			  info->KPCR[i].QuadPart = (uintptr_t)__readfsword(0x1c);
		#endif
			
		}
	}

	KeRevertToUserAffinityThread(); 
	// xxx: I don't think this works for reverting to the real original affinity but the alternative requires Vista or higher.
	// xxx: The WDK10 does not support WinXP anymore! 
	//      Do we favor the newer Vista+ Ex version? To perfectly restore the old affinity?

	return;
}
