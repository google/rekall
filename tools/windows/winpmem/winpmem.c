#include "winpmem.h"

#include "read.h"

NTSTATUS IoUnload(IN PDRIVER_OBJECT DriverObject) {
  UNICODE_STRING DeviceLinkUnicodeString;
  NTSTATUS NtStatus;
  PDEVICE_OBJECT pDeviceObject = DriverObject->DeviceObject;

  //
  // Initiliaze the string for the symbolic link.
  //
  RtlInitUnicodeString (&DeviceLinkUnicodeString, L"\\DosDevices\\" PMEM_DEVICE_NAME);

  //
  // We delete the symbolic link we've created.
  //
  NtStatus = IoDeleteSymbolicLink (&DeviceLinkUnicodeString);

  if (DriverObject != NULL) {
    //
    // We delete the device.
    //
    IoDeleteDevice(pDeviceObject);
  }

  return NtStatus;
}


/*++
Function Name: MmGetPhysicalMemoryBlock

Overview:
        - This function aims at retrieving MmPhysicalMemoryBlock, regardless
        of the host version.

        The caller has to free the memory block.

        - I suggest to recreate PHYSICAL_MEMORY_DESCRIPTOR with following informations:
         NumberOfPages = sizeof(RAM) >> PAGE_SHIFT
         NumberOfRuns = 1
         BasePage = 1
         PageCount = NumberOfPages - BasePage
         Therefore, by using a single Run we can have a valid PHYSICAL_MEM_DESCRIPTOR.

Parameters:
        -

Environment:
        - Kernel Mode.

Return Values:
        - PPHYSICAL_MEMORY_DESCRIPTOR
--*/
static PPHYSICAL_MEMORY_DESCRIPTOR MmGetPhysicalMemoryBlock(VOID) {
  PPHYSICAL_MEMORY_DESCRIPTOR MmPhysicalMemoryBlock;
  PPHYSICAL_MEMORY_RANGE MmPhysicalMemoryRange;
  ULONG MemoryBlockSize;
  PFN_NUMBER NumberOfPages;
  ULONG NumberOfRuns;
  ULONG Run;

  //
  // PHYSICAL_MEMORY_DESCRIPTOR isn't exported into KDDEBUGGER_DATA64
  // NT 5.0 and below. But MmGetPhysicalMemoryRanges() computes
  // PHYSICAL_MEMORY_RANGE with PHYSICAL_MEMORY_DESCRIPTOR. Then,
  // We can easily rewrite PHYSICAL_MEMORY_DESCRIPTOR.
  //
  MmPhysicalMemoryRange = MmGetPhysicalMemoryRanges();

  //
  // Invalid ?
  //
  if (MmPhysicalMemoryRange == NULL) return NULL;

  //
  // Compute the number of runs and the number of pages
  //
  NumberOfRuns = 0;
  NumberOfPages = 0;
  while ((MmPhysicalMemoryRange[NumberOfRuns].BaseAddress.QuadPart != 0) &&
         (MmPhysicalMemoryRange[NumberOfRuns].NumberOfBytes.QuadPart != 0)) {
    NumberOfRuns++;
    NumberOfPages += (PFN_NUMBER)BYTES_TO_PAGES(
        MmPhysicalMemoryRange[NumberOfRuns].NumberOfBytes.QuadPart);
  }

  //
  // Invalid ?
  //
  if (NumberOfRuns == 0) return NULL;

  //
  // Compute the size of the pool to allocate and then allocate
  //
  MemoryBlockSize = (sizeof(ULONG) + sizeof(PFN_NUMBER) +
                     sizeof(PHYSICAL_MEMORY_RUN) * NumberOfRuns);

  MmPhysicalMemoryBlock = ExAllocatePoolWithTag(NonPagedPool, MemoryBlockSize,
                                                '  mM');

  //
  // Define PHYSICAL_MEMORY_DESCRIPTOR Header.=
  //
  MmPhysicalMemoryBlock->NumberOfRuns = NumberOfRuns;
  MmPhysicalMemoryBlock->NumberOfPages = NumberOfPages;

  for (Run = 0; Run < NumberOfRuns; Run++) {
    //
    // BasePage
    //
    MmPhysicalMemoryBlock->Run[Run].BasePage = (PFN_NUMBER)MI_CONVERT_PHYSICAL_TO_PFN(
       MmPhysicalMemoryRange[NumberOfRuns].BaseAddress.QuadPart);

    //
    // PageCount
    //
    MmPhysicalMemoryBlock->Run[Run].PageCount = (PFN_NUMBER)BYTES_TO_PAGES(
       MmPhysicalMemoryRange[Run].NumberOfBytes.QuadPart);
  }

  return MmPhysicalMemoryBlock;
}


/*
  Gets information about the memory layout.

  - The current value of CR3 which is the kernel DTB.
  - The location of the kernel PCR block.
  - The Physical memory address ranges.

  This must be done in the context of the first CPU. See this:
  http://www.msuiche.net/2009/01/05/multi-processors-and-kdversionblock/
 */
int AddMemoryRanges(struct PmemMemroyInfo *info, int len) {
  PPHYSICAL_MEMORY_RANGE MmPhysicalMemoryRange;
  int i = 0;
  int required_length;
  ULONG CR3, KPCR;

  /* Make sure we run on the first CPU so the KPCR is valid. */

  KeSetSystemAffinityThread(1);

  info->CR3.QuadPart = __readcr3();
  info->KPCR.QuadPart = 0x12345678;
  KeRevertToUserAffinityThread();

  // Enumerate address ranges.
  MmPhysicalMemoryRange = MmGetPhysicalMemoryRanges();

  if (MmPhysicalMemoryRange == NULL) {
    return -1;
  };

  /** Find out how many ranges there are. */
  for(i=0; (MmPhysicalMemoryRange[i].BaseAddress.QuadPart) &&
          (MmPhysicalMemoryRange[i].NumberOfBytes.QuadPart); i++) {
    i++;
  }

  required_length = sizeof(struct PmemMemroyInfo) +
      i * sizeof(PHYSICAL_MEMORY_RANGE);

  /* Do we have enough space? */
  if(len < required_length) {
    return -1;
  };

  info->NumberOfRuns = i;
  RtlCopyMemory(&info->Run[0], MmPhysicalMemoryRange,
                i * sizeof(PHYSICAL_MEMORY_RANGE));

  ExFreePool(MmPhysicalMemoryRange);

  return required_length;
};


static NTSTATUS wddCreate(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
  PDEVICE_EXTENSION ext=(PDEVICE_EXTENSION)DeviceObject->DeviceExtension;
  PIO_STACK_LOCATION IrpStack = IoGetCurrentIrpStackLocation(Irp);

  WinDbgPrint("Created driver.");
  ext->MemoryHandle = 0;
  ext->descriptor = MmGetPhysicalMemoryBlock();

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

/*++
Function Name: wddDispatchDeviceControl

Overview:
        - .

Parameters:
        - DeviceObject: Pointer to PDEVICE_OBJECT.

        - Irp: Pointer to Irp.

Return Values:
        - NTSTATUS
--*/
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

      WinDbgPrint("Returning info on the system memory.\n");
      if(res > 0) {
        Irp->IoStatus.Information = res;
        NtStatus = STATUS_SUCCESS;
      } else {
        NtStatus = STATUS_INFO_LENGTH_MISMATCH;
      };

      Irp->IoStatus.Status = NtStatus;
    }; break;
  }

  //
  // Leaving.
  //
  IoCompleteRequest(Irp,IO_NO_INCREMENT);
  return STATUS_SUCCESS;
}


/*++
Function Name: DriverEntry

Overview:
        - Entry point.

Parameters:
        - DriverObject: Pointer to PDRIVER_OBJECT.

        - RegistryPath: Pointer to PUNICODE_STRING.

Return Values:
        - NTSTATUS
--*/
NTSTATUS DriverEntry (IN PDRIVER_OBJECT DriverObject,
                      IN PUNICODE_STRING RegistryPath)
{
  UNICODE_STRING DeviceName, DeviceLink;
  NTSTATUS NtStatus;
  PDEVICE_OBJECT DeviceObject = NULL;

  WinDbgPrint("WinPMEM - " PMEM_VERSION " - Physical memory acquisition\n");
  WinDbgPrint("Copyright (c) 2012, Michael Cohen <scudette@gmail.com> based "
              "on win32dd code by Matthieu Suiche <http://www.msuiche.net>\n");

  //
  // We define the unicode string for our device.
  //
  RtlInitUnicodeString (&DeviceName, L"\\Device\\" PMEM_DEVICE_NAME);

  //
  // We create our secure device.
  // http://msdn.microsoft.com/en-us/library/aa490540.aspx
  //
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
  //
  // Define unloading function.
  //
  DriverObject->DriverUnload = IoUnload;

  // Use buffered IO - a bit slower but simpler to implement, and more
  // efficient for small reads.
  SetFlag(DeviceObject->Flags, DO_BUFFERED_IO );
  ClearFlag(DeviceObject->Flags, DO_DIRECT_IO );
  ClearFlag(DeviceObject->Flags, DO_DEVICE_INITIALIZING);

  //
  // We define the memory dumper symbolic name.
  //
  RtlInitUnicodeString (&DeviceLink, L"\\DosDevices\\" PMEM_DEVICE_NAME);

  //
  // We create it's symbolic name.
  //
  NtStatus = IoCreateSymbolicLink (&DeviceLink,
                                   &DeviceName);

  //
  // If we reach this case, we cannot continue.
  //
  if (!NT_SUCCESS(NtStatus)) {
    WinDbgPrint ("IoCreateSymbolicLink failed. => %08X\n", NtStatus);
    IoDeleteDevice (DeviceObject);
  }

  return NtStatus;
}
