#include "winpmem.h"
#include "api.h"
#include "kd.h"

struct Pmem_KernelExports_t Pmem_KernelExports;


NTSTATUS PmemGetProcAddresses() {
  void *image_base = KernelGetModuleBaseByPtr(NtBuildNumber, "NtBuildNumber");
  char key[sizeof(OBFUSCATION_KEY)] = OBFUSCATION_KEY;
  void *api = NULL;


  RtlZeroMemory(&Pmem_KernelExports, sizeof(Pmem_KernelExports));

  if (!image_base) {
    goto error;
  };

  // If any of the below APIs fail, they will have a NULL pointer in the export
  // table - this will cause that acquisition method to be rejected.
  if (image_base) {
    {
      int i;
      char parameter[sizeof(X_MmGetPhysicalMemoryRanges)] =
        X_MmGetPhysicalMemoryRanges;


      for(i=0; i<min(sizeof(parameter), sizeof(key)); i++) {
        parameter[i] ^= key[i];
      };

      WinDbgPrint("Fetching API %s\n", parameter);
      api = KernelGetProcAddress(image_base, parameter);
      Pmem_KernelExports.MmGetPhysicalMemoryRanges = api;
    };

    {
      int i;
      char parameter[sizeof(X_MmGetVirtualForPhysical)] =
        X_MmGetVirtualForPhysical;

      for(i=0; i<min(sizeof(parameter), sizeof(key)); i++) {
        parameter[i] ^= key[i];
      };

      WinDbgPrint("Fetching API %s\n", parameter);
      api = KernelGetProcAddress(image_base, parameter);
      Pmem_KernelExports.MmGetVirtualForPhysical = api;
    };

    {
      int i;
      char parameter[sizeof(X_MmMapIoSpace)] = X_MmMapIoSpace;
      for(i=0; i<min(sizeof(parameter), sizeof(key)); i++) {
        parameter[i] ^= key[i];
      };

      WinDbgPrint("Fetching API %s\n", parameter);
      api = KernelGetProcAddress(image_base, parameter);
      Pmem_KernelExports.MmMapIoSpace = api;
    };

    {
      int i;
      char parameter[sizeof(X_MmUnmapIoSpace)] = X_MmUnmapIoSpace;
      for(i=0; i<min(sizeof(parameter), sizeof(key)); i++) {
        parameter[i] ^= key[i];
      };

      WinDbgPrint("Fetching API %s\n", parameter);
      api = KernelGetProcAddress(image_base, parameter);
      Pmem_KernelExports.MmUnmapIoSpace = api;
    };
  };

  return STATUS_SUCCESS;

 error:
  return STATUS_INVALID_PARAMETER;
};
