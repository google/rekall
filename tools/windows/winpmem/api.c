#include "winpmem.h"
#include "api.h"
#include "kd.h"

struct Pmem_KernelExports_t Pmem_KernelExports;


NTSTATUS PmemGetProcAddresses() {
  void *image_base = KernelGetModuleBaseByPtr(NtBuildNumber, "NtBuildNumber");
  char key[sizeof(OBFUSCATION_KEY)] = OBFUSCATION_KEY;

  RtlZeroMemory(&Pmem_KernelExports, sizeof(Pmem_KernelExports));

  if (image_base) {
    {
      int i;
      char parameter[sizeof(X_MmGetPhysicalMemoryRanges)] =
        X_MmGetPhysicalMemoryRanges;

      for(i=0; i<min(sizeof(parameter), sizeof(key)); i++) {
        parameter[i] ^= key[i];
      };

      WinDbgPrint("Fetching API %s\n", parameter);
      Pmem_KernelExports.MmGetPhysicalMemoryRanges =
        KernelGetProcAddress(image_base, parameter);
    };

    {
      int i;
      char parameter[sizeof(X_MmGetVirtualForPhysical)] =
        X_MmGetVirtualForPhysical;

      for(i=0; i<min(sizeof(parameter), sizeof(key)); i++) {
        parameter[i] ^= key[i];
      };

      WinDbgPrint("Fetching API %s\n", parameter);
      Pmem_KernelExports.MmGetVirtualForPhysical =
        KernelGetProcAddress(image_base, parameter);
    };

    {
      int i;
      char parameter[sizeof(X_MmMapIoSpace)] = X_MmMapIoSpace;
      for(i=0; i<min(sizeof(parameter), sizeof(key)); i++) {
        parameter[i] ^= key[i];
      };

      WinDbgPrint("Fetching API %s\n", parameter);
      Pmem_KernelExports.MmMapIoSpace =
        KernelGetProcAddress(image_base, parameter);
    };

    {
      int i;
      char parameter[sizeof(X_MmUnmapIoSpace)] = X_MmUnmapIoSpace;
      for(i=0; i<min(sizeof(parameter), sizeof(key)); i++) {
        parameter[i] ^= key[i];
      };

      WinDbgPrint("Fetching API %s\n", parameter);
      Pmem_KernelExports.MmUnmapIoSpace =
        KernelGetProcAddress(image_base, parameter);
    };
  };

  return STATUS_SUCCESS;
};
