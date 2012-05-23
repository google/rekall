/*
   Copyright 2012 Michael Cohen <scudette@gmal.com>

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

#include "read.h"


// The following globals are populated in the kernel context from DriverEntry
// and reported to the user context.

// The kernel CR3
LARGE_INTEGER CR3;



NTSTATUS IoUnload(IN PDRIVER_OBJECT DriverObject) {
  UNICODE_STRING DeviceLinkUnicodeString;
  NTSTATUS NtStatus;
  PDEVICE_OBJECT pDeviceObject = DriverObject->DeviceObject;

  RtlInitUnicodeString (&DeviceLinkUnicodeString, L"\\DosDevices\\" PMEM_DEVICE_NAME);
  NtStatus = IoDeleteSymbolicLink (&DeviceLinkUnicodeString);

  if (DriverObject != NULL) {
    IoDeleteDevice(pDeviceObject);
  }

  return NtStatus;
}


/*
  Gets information about the memory layout.

  - The Physical memory address ranges.
 */
int AddMemoryRanges(struct PmemMemroyInfo *info, int len) {
  PPHYSICAL_MEMORY_RANGE MmPhysicalMemoryRange;
  int number_of_runs = 0;
  int required_length;

  // Enumerate address ranges.
  MmPhysicalMemoryRange = MmGetPhysicalMemoryRanges();

  if (MmPhysicalMemoryRange == NULL) {
    return -1;
  };

  /** Find out how many ranges there are. */
  for(number_of_runs=0; (MmPhysicalMemoryRange[number_of_runs].BaseAddress.QuadPart) ||
        (MmPhysicalMemoryRange[number_of_runs].NumberOfBytes.QuadPart); number_of_runs++);

  required_length = (sizeof(struct PmemMemroyInfo) +
                     number_of_runs * sizeof(PHYSICAL_MEMORY_RANGE));

  /* Do we have enough space? */
  if(len < required_length) {
    return -1;
  };

  RtlZeroMemory(info, required_length);

  info->NumberOfRuns = number_of_runs;
  RtlCopyMemory(&info->Run[0], MmPhysicalMemoryRange,
                number_of_runs * sizeof(PHYSICAL_MEMORY_RANGE));

  ExFreePool(MmPhysicalMemoryRange);

  return required_length;
};


static NTSTATUS wddCreate(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
  PDEVICE_EXTENSION ext=(PDEVICE_EXTENSION)DeviceObject->DeviceExtension;
  PIO_STACK_LOCATION IrpStack = IoGetCurrentIrpStackLocation(Irp);

  WinDbgPrint("Created driver.");
  ext->MemoryHandle = 0;

  Irp->IoStatus.Status = STATUS_SUCCESS;
  Irp->IoStatus.Information = 0;

  IoCompleteRequest(Irp,IO_NO_INCREMENT);
  return STATUS_SUCCESS;
};

static NTSTATUS wddClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
 PDEVICE_EXTENSION ext=(PDEVICE_EXTENSION)DeviceObject->DeviceExtension;
 PIO_STACK_LOCATION IrpStack = IoGetCurrentIrpStackLocation(Irp);

 WinDbgPrint("Close driver.");

 if(ext->MemoryHandle != 0) {
   ZwClose(ext->MemoryHandle);
 };

 Irp->IoStatus.Status = STATUS_SUCCESS;
 Irp->IoStatus.Information = 0;

 IoCompleteRequest(Irp,IO_NO_INCREMENT);
 return STATUS_SUCCESS;
}

NTSTATUS wddDispatchDeviceControl(IN PDEVICE_OBJECT DeviceObject,
                                      IN PIRP Irp)
{
  UNICODE_STRING DestinationPath;
  PIO_STACK_LOCATION IrpStack;
  NTSTATUS NtStatus;
  ULONG IoControlCode;
  PVOID IoBuffer;
  PULONG OutputBuffer;
  PDEVICE_EXTENSION ext=(PDEVICE_EXTENSION)DeviceObject->DeviceExtension;
  ULONG InputLen, OutputLen;

  ULONG Level;
  ULONG Type;

  Irp->IoStatus.Status = STATUS_SUCCESS;
  Irp->IoStatus.Information = 0;

  IrpStack = IoGetCurrentIrpStackLocation(Irp);

  IoBuffer = Irp->AssociatedIrp.SystemBuffer;
  OutputLen = IrpStack->Parameters.DeviceIoControl.OutputBufferLength;
  InputLen = IrpStack->Parameters.DeviceIoControl.InputBufferLength;
  IoControlCode = IrpStack->Parameters.DeviceIoControl.IoControlCode;

  switch ((IoControlCode & 0xFFFFFF0F)) {

    // Return information about memory layout etc through this ioctrl.
  case IOCTL_GET_INFO: {
    struct PmemMemroyInfo *info = (void *)IoBuffer;
    int res = AddMemoryRanges(info, OutputLen);

    // We are currently running in user context which means __readcr3() will
    // return the process CR3. So we return the kernel CR3 we found before.
    info->CR3.QuadPart = CR3.QuadPart;

    WinDbgPrint("Returning info on the system memory.\n");
    if(res > 0) {
      Irp->IoStatus.Information = res;
      NtStatus = STATUS_SUCCESS;
    } else {
      NtStatus = STATUS_INFO_LENGTH_MISMATCH;
    };

    Irp->IoStatus.Status = NtStatus;
  }; break;

  case IOCTL_SET_MODE: {
    WinDbgPrint("Setting Acquisition mode.\n");

    if (InputLen == sizeof(struct PmemMemoryControl)) {
      struct PmemMemoryControl *ctrl = (void *)IoBuffer;

      ext->mode = ctrl->mode;
      NtStatus = STATUS_SUCCESS;

      switch(ctrl->mode) {
      case ACQUISITION_MODE_PHYSICAL_MEMORY:
        WinDbgPrint("Using physical memory device for acquisition.\n");
        break;

      case ACQUISITION_MODE_MAP_IO_SPACE:
        WinDbgPrint("Using MmMapIoSpace for acquisition.\n");
        break;

      default:
        WinDbgPrint("Invalid acquisition mode %d.\n", ctrl->mode);
        NtStatus = STATUS_INVALID_PARAMETER;
      };

    } else {
      NtStatus = STATUS_INFO_LENGTH_MISMATCH;
    };

    Irp->IoStatus.Status = NtStatus;
  }; break;

  default: {
    WinDbgPrint("Invalid IOCTRL %d\n", IoControlCode);
  };
  }

  IoCompleteRequest(Irp,IO_NO_INCREMENT);
  return STATUS_SUCCESS;
}


NTSTATUS DriverEntry (IN PDRIVER_OBJECT DriverObject,
                      IN PUNICODE_STRING RegistryPath)
{
  UNICODE_STRING DeviceName, DeviceLink;
  NTSTATUS NtStatus;
  PDEVICE_OBJECT DeviceObject = NULL;

  WinDbgPrint("WinPMEM - " PMEM_VERSION " - Physical memory acquisition\n");
  WinDbgPrint("Copyright (c) 2012, Michael Cohen <scudette@gmail.com> based "
              "on win32dd code by Matthieu Suiche <http://www.msuiche.net>\n");

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
  DriverObject->MajorFunction[IRP_MJ_READ] =  PmemRead;
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

  return NtStatus;
}
