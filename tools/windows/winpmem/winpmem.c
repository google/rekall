/*
  Copyright 2014 Michael Cohen <scudette@gmail.com>

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

#include "winpmem.h"
#include "pte_mmap_windows.h"
#include "api.h"
#include "read.h"
#include "kd.h"
#include "pci.h"


// The following globals are populated in the kernel context from DriverEntry
// and reported to the user context.

// The kernel CR3
LARGE_INTEGER CR3;

DRIVER_UNLOAD IoUnload;
VOID IoUnload(IN PDRIVER_OBJECT DriverObject) {
  UNICODE_STRING DeviceLinkUnicodeString;
  PDEVICE_OBJECT pDeviceObject = DriverObject->DeviceObject;
  PDEVICE_EXTENSION ext=(PDEVICE_EXTENSION)pDeviceObject->DeviceExtension;

  RtlInitUnicodeString (&DeviceLinkUnicodeString, L"\\DosDevices\\"
			PMEM_DEVICE_NAME);
  IoDeleteSymbolicLink (&DeviceLinkUnicodeString);

  if (DriverObject != NULL) {
    IoDeleteDevice(pDeviceObject);
  }

  if(ext->pte_mmapper) {
    pte_mmap_windows_delete(ext->pte_mmapper);
  };
}


/*
  Gets information about the memory layout.

  - The Physical memory address ranges.
*/
NTSTATUS AddMemoryRanges(struct PmemMemoryInfo *info, int len) {
  PPHYSICAL_MEMORY_RANGE MmPhysicalMemoryRange;
  int number_of_runs = 0;
  int required_length;

  // Enumerate address ranges.
  MmPhysicalMemoryRange = Pmem_KernelExports.MmGetPhysicalMemoryRanges();

  if (MmPhysicalMemoryRange == NULL) {
    return STATUS_ACCESS_DENIED;
  };

  /** Find out how many ranges there are. */
  for(number_of_runs=0;
      (MmPhysicalMemoryRange[number_of_runs].BaseAddress.QuadPart) ||
        (MmPhysicalMemoryRange[number_of_runs].NumberOfBytes.QuadPart);
      number_of_runs++);

  required_length = (sizeof(struct PmemMemoryInfo) +
                     number_of_runs * sizeof(PHYSICAL_MEMORY_RANGE));

  /* Do we have enough space? */
  if(len < required_length) {
    return STATUS_INFO_LENGTH_MISMATCH;
  };

  RtlZeroMemory(info, required_length);

  info->NumberOfRuns.QuadPart = number_of_runs;
  RtlCopyMemory(&info->Run[0], MmPhysicalMemoryRange,
                number_of_runs * sizeof(PHYSICAL_MEMORY_RANGE));

  ExFreePool(MmPhysicalMemoryRange);

  return STATUS_SUCCESS;
};

__drv_dispatchType(IRP_MJ_CREATE)
DRIVER_DISPATCH wddCreate;
static NTSTATUS wddCreate(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
  PDEVICE_EXTENSION ext=(PDEVICE_EXTENSION)DeviceObject->DeviceExtension;
  PIO_STACK_LOCATION IrpStack = IoGetCurrentIrpStackLocation(Irp);

  Irp->IoStatus.Status = STATUS_SUCCESS;
  Irp->IoStatus.Information = 0;

  IoCompleteRequest(Irp,IO_NO_INCREMENT);
  return STATUS_SUCCESS;
};


__drv_dispatchType(IRP_MJ_CLOSE)
DRIVER_DISPATCH wddClose;
static NTSTATUS wddClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
  PDEVICE_EXTENSION ext=(PDEVICE_EXTENSION)DeviceObject->DeviceExtension;
  PIO_STACK_LOCATION IrpStack = IoGetCurrentIrpStackLocation(Irp);

  if(ext->MemoryHandle != 0) {
    ZwClose(ext->MemoryHandle);
    ext->MemoryHandle = 0;
  };

  Irp->IoStatus.Status = STATUS_SUCCESS;
  Irp->IoStatus.Information = 0;

  IoCompleteRequest(Irp,IO_NO_INCREMENT);

  return STATUS_SUCCESS;
}

__drv_dispatchType(IRP_MJ_DEVICE_CONTROL)
DRIVER_DISPATCH wddDispatchDeviceControl;
NTSTATUS wddDispatchDeviceControl(IN PDEVICE_OBJECT DeviceObject,
				  IN PIRP Irp)
{
  UNICODE_STRING DestinationPath;
  PIO_STACK_LOCATION IrpStack;
  NTSTATUS status = STATUS_INVALID_PARAMETER;
  ULONG IoControlCode;
  PVOID IoBuffer;
  PULONG OutputBuffer;
  PDEVICE_EXTENSION ext;
  ULONG InputLen, OutputLen;

  ULONG Level;
  ULONG Type;

  // We must be running in PASSIVE_LEVEL or we bluescreen here. We
  // theoretically should always be running at PASSIVE_LEVEL here, but
  // in case we ended up here at the wrong IRQL its better to bail
  // than to bluescreen.
  if(KeGetCurrentIrql() != PASSIVE_LEVEL) {
    status = STATUS_ABANDONED;
    goto exit;
  };

  ext = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;

  Irp->IoStatus.Information = 0;

  IrpStack = IoGetCurrentIrpStackLocation(Irp);

  IoBuffer = Irp->AssociatedIrp.SystemBuffer;
  OutputLen = IrpStack->Parameters.DeviceIoControl.OutputBufferLength;
  InputLen = IrpStack->Parameters.DeviceIoControl.InputBufferLength;
  IoControlCode = IrpStack->Parameters.DeviceIoControl.IoControlCode;

  switch ((IoControlCode & 0xFFFFFF0F)) {

  // The old deprecated ioctrl interface for backwards
  // compatibility. Do not use for new code.
  case IOCTL_GET_INFO_DEPRECATED: {
    char *buffer = ExAllocatePoolWithTag(PagedPool, 0x1000, PMEM_POOL_TAG);

    if (buffer) {
      struct DeprecatedPmemMemoryInfo *info = (void *)IoBuffer;
      struct PmemMemoryInfo *memory_info = (void *)buffer;

      status = AddMemoryRanges(memory_info, 0x1000);
      if (status != STATUS_SUCCESS) {
        ExFreePoolWithTag(buffer, PMEM_POOL_TAG);
        goto exit;
      };

      info->CR3.QuadPart = CR3.QuadPart;
      info->NumberOfRuns = (unsigned long)memory_info->NumberOfRuns.QuadPart;

      // Is there enough space in the user supplied buffer?
      if (OutputLen < (info->NumberOfRuns * sizeof(PHYSICAL_MEMORY_RANGE) +
                       sizeof(struct DeprecatedPmemMemoryInfo))) {
        status = STATUS_INFO_LENGTH_MISMATCH;
        ExFreePoolWithTag(buffer, PMEM_POOL_TAG);
        goto exit;
      };

      // Copy the runs over.
      RtlCopyMemory(&info->Run[0], &memory_info->Run[0],
                    info->NumberOfRuns * sizeof(PHYSICAL_MEMORY_RANGE));

      // This is the total length of the response.
      Irp->IoStatus.Information =
        sizeof(struct DeprecatedPmemMemoryInfo) +
        info->NumberOfRuns * sizeof(PHYSICAL_MEMORY_RANGE);

      WinDbgPrint("Returning info on the system memory using deprecated "
		  "interface!\n");

      ExFreePoolWithTag(buffer, PMEM_POOL_TAG);
      status = STATUS_SUCCESS;
    };
  }; break;

    // Return information about memory layout etc through this ioctrl.
  case IOCTL_GET_INFO: {
    struct PmemMemoryInfo *info = (void *)IoBuffer;

    if (OutputLen < sizeof(struct PmemMemoryInfo)) {
        status = STATUS_INFO_LENGTH_MISMATCH;
        goto exit;
    };

    // Ensure we clear the buffer first.
    RtlZeroMemory(IoBuffer, sizeof(struct PmemMemoryInfo));

    // Get the memory ranges according to the mode.
    if (ext->mode == ACQUISITION_MODE_PTE_MMAP_WITH_PCI_PROBE) {
      status = PCI_AddMemoryRanges(info, OutputLen);
    } else {
      status = AddMemoryRanges(info, OutputLen);
    }

    if (status != STATUS_SUCCESS) {
      goto exit;
    };

    WinDbgPrint("Returning info on the system memory.\n");

    // We are currently running in user context which means __readcr3() will
    // return the process CR3. So we return the kernel CR3 we found
    // when loading.
    info->CR3.QuadPart = CR3.QuadPart;

    info->NtBuildNumber.QuadPart = *NtBuildNumber;
    info->NtBuildNumberAddr.QuadPart = (uintptr_t)NtBuildNumber;
    info->KernBase.QuadPart = (uintptr_t)KernelGetModuleBaseByPtr(
       NtBuildNumber, "NtBuildNumber");

    // Fill in KPCR.
    GetKPCR(info);

    // This is the length of the response.
    Irp->IoStatus.Information =
      sizeof(struct PmemMemoryInfo) +
      info->NumberOfRuns.LowPart * sizeof(PHYSICAL_MEMORY_RANGE);

    status = STATUS_SUCCESS;
  }; break;

  case IOCTL_SET_MODE: {
    WinDbgPrint("Setting Acquisition mode.\n");

    /* First u32 is the acquisition mode. */
    if (InputLen >= sizeof(u32)) {
      enum PMEM_ACQUISITION_MODE mode = *(u32 *)IoBuffer;

      ext->mode = mode;

      switch(mode) {
      case ACQUISITION_MODE_PHYSICAL_MEMORY:
        // These are all the requirements for this method.
        if (!Pmem_KernelExports.MmGetPhysicalMemoryRanges) {
          WinDbgPrint("Kernel APIs required for this method are not "
                      "available.");
          status = STATUS_UNSUCCESSFUL;
        } else {
          WinDbgPrint("Using physical memory device for acquisition.\n");
          status = STATUS_SUCCESS;
        };
        break;

      case ACQUISITION_MODE_MAP_IO_SPACE:
        if (!Pmem_KernelExports.MmGetPhysicalMemoryRanges ||
            !Pmem_KernelExports.MmMapIoSpace ||
            !Pmem_KernelExports.MmUnmapIoSpace) {
          WinDbgPrint("Kernel APIs required for this method are not "
                      "available.");
          status = STATUS_UNSUCCESSFUL;
        } else {
          WinDbgPrint("Using MmMapIoSpace for acquisition.\n");
          status = STATUS_SUCCESS;
        };
        break;

      case ACQUISITION_MODE_PTE_MMAP:
        if (!Pmem_KernelExports.MmGetVirtualForPhysical ||
            !Pmem_KernelExports.MmGetPhysicalMemoryRanges ||
            !ext->pte_mmapper) {
          WinDbgPrint("Kernel APIs required for this method are not "
                      "available.");
          status = STATUS_UNSUCCESSFUL;
        } else {
          WinDbgPrint("Using PTE Remapping for acquisition.\n");
          status = STATUS_SUCCESS;
        };
        break;

      case ACQUISITION_MODE_PTE_MMAP_WITH_PCI_PROBE:
        if (!Pmem_KernelExports.MmGetVirtualForPhysical ||
            !ext->pte_mmapper) {
          WinDbgPrint("Kernel APIs required for this method are not "
                      "available.");
          status = STATUS_UNSUCCESSFUL;
        } else {
          WinDbgPrint("Using PTE Remapping with PCI probe for acquisition.\n");
          status = STATUS_SUCCESS;
        };
        break;

      default:
        WinDbgPrint("Invalid acquisition mode %d.\n", mode);
        status = STATUS_INVALID_PARAMETER;
      };

    } else {
      status = STATUS_INFO_LENGTH_MISMATCH;
    };
  }; break;

#if PMEM_WRITE_ENABLED == 1
  case IOCTL_WRITE_ENABLE: {
    ext->WriteEnabled = !ext->WriteEnabled;
    WinDbgPrint("Write mode is %d. Do you know what you are doing?\n",
		ext->WriteEnabled);
    status = STATUS_SUCCESS;
  }; break;
#endif

  default: {
    WinDbgPrint("Invalid IOCTRL %d\n", IoControlCode);
    status = STATUS_INVALID_PARAMETER;
  };
  }

 exit:
  Irp->IoStatus.Status = status;
  IoCompleteRequest(Irp,IO_NO_INCREMENT);
  return status;
}


DRIVER_INITIALIZE DriverEntry;
NTSTATUS DriverEntry (IN PDRIVER_OBJECT DriverObject,
                      IN PUNICODE_STRING RegistryPath)
{
  UNICODE_STRING DeviceName, DeviceLink;
  NTSTATUS NtStatus;
  PDEVICE_OBJECT DeviceObject = NULL;
  PDEVICE_EXTENSION extension;

  WinDbgPrint("WinPMEM - " PMEM_VERSION " - Physical memory acquisition\n");

#if PMEM_WRITE_ENABLED == 1
  WinDbgPrint("WinPMEM write support available!");
#endif

  WinDbgPrint("Copyright (c) 2014, Michael Cohen <scudette@gmail.com>\n");

  // Initialize import tables:
  if(PmemGetProcAddresses() != STATUS_SUCCESS) {
    WinDbgPrint("Failed to initialize import table. Aborting.\n");
    goto error;
  };

  RtlInitUnicodeString (&DeviceName, L"\\Device\\" PMEM_DEVICE_NAME);

  // We create our secure device.
  // http://msdn.microsoft.com/en-us/library/aa490540.aspx
  NtStatus = IoCreateDeviceSecure(DriverObject,
                                  sizeof(DEVICE_EXTENSION),
                                  &DeviceName,
                                  FILE_DEVICE_UNKNOWN,
                                  FILE_DEVICE_SECURE_OPEN,
                                  FALSE,
                                  &SDDL_DEVOBJ_SYS_ALL_ADM_ALL,
                                  &GUID_DEVCLASS_PMEM_DUMPER,
                                  &DeviceObject);

  if (!NT_SUCCESS(NtStatus)) {
    WinDbgPrint ("IoCreateDevice failed. => %08X\n", NtStatus);
    return NtStatus;
  }

  DriverObject->MajorFunction[IRP_MJ_CREATE] = wddCreate;
  DriverObject->MajorFunction[IRP_MJ_CLOSE] = wddClose;
  DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = wddDispatchDeviceControl;
  DriverObject->MajorFunction[IRP_MJ_READ] = PmemRead;

#if PMEM_WRITE_ENABLED == 1
  {
    // Make sure that the drivers with write support are clearly marked as such.
    static char TAG[] = "Write Supported";
  }

  // Support writing.
  DriverObject->MajorFunction[IRP_MJ_WRITE] = PmemWrite;
#endif
  DriverObject->DriverUnload = IoUnload;

  // Use buffered IO - a bit slower but simpler to implement, and more
  // efficient for small reads.
  SetFlag(DeviceObject->Flags, DO_BUFFERED_IO );
  ClearFlag(DeviceObject->Flags, DO_DIRECT_IO );
  ClearFlag(DeviceObject->Flags, DO_DEVICE_INITIALIZING);

  RtlInitUnicodeString (&DeviceLink, L"\\DosDevices\\" PMEM_DEVICE_NAME);

  NtStatus = IoCreateSymbolicLink (&DeviceLink, &DeviceName);

  if (!NT_SUCCESS(NtStatus)) {
    WinDbgPrint ("IoCreateSymbolicLink failed. => %08X\n", NtStatus);
    IoDeleteDevice (DeviceObject);
  }

  // Populate globals in kernel context.
  CR3.QuadPart = __readcr3();

  // Initialize the device extension with safe defaults.
  extension = DeviceObject->DeviceExtension;
  extension->mode = ACQUISITION_MODE_PHYSICAL_MEMORY;
  extension->MemoryHandle = 0;

#if _WIN64
  // Disable pte mapping for 32 bit systems.
  extension->pte_mmapper = pte_mmap_windows_new();
  extension->pte_mmapper->loglevel = PTE_ERR;
#else
  extension->pte_mmapper = NULL;
#endif

  WinDbgPrint("Driver intialization completed.");
  return NtStatus;

 error:
  return STATUS_UNSUCCESSFUL;
}
