/*++
    Kernel Land Physical Memory Dumper
    Copyright (C) 2008 Matthieu Suiche http://www.msuiche.net 

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

Module Name:

    - win32dd.c

Abstract:

    - This driver aims to provide a full dump of the physical memory (RAM).
    - Because since Windows 2003 SP1, access to \\PhysicalMemory has been disabled from user-land,
      and there are no public 100% kernel dumper. I decide to release mine as an open source project.


Environment:

    - Kernel mode

Revision History:
    - Michael Cohen (scudette@gmail.com)

    - Matthieu Suiche

--*/

#include "precomp.h"
#include "read.h"

ULONG IopFinalRawDumpStatus = STATUS_PEND;
ULONG IopFinalCrashDumpStatus = STATUS_PEND;


/*++
Function Name: IoUnload

Overview:
        - .

Parameters:
        - DriverObject: Pointer to PDRIVER_OBJECT.

Return Values:
        - NTSTATUS
--*/
NTSTATUS IoUnload(IN PDRIVER_OBJECT DriverObject)
{
UNICODE_STRING DeviceLinkUnicodeString;
NTSTATUS NtStatus;

PDEVICE_OBJECT pDeviceObject = DriverObject->DeviceObject;

    //
    // Initiliaze the string for the symbolic link.
    //
    RtlInitUnicodeString (&DeviceLinkUnicodeString, L"\\DosDevices\\" WIN32DD_DEVICE_NAME);

    //
    // We delete the symbolic link we've created.
    //
    NtStatus = IoDeleteSymbolicLink (&DeviceLinkUnicodeString);

    if (DriverObject != NULL)
    {
        //
        // We delete the device.
        //
        IoDeleteDevice(pDeviceObject);
    }

    return NtStatus;
}


static NTSTATUS wddCreate(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) {
  PDEVICE_EXTENSION ext=(PDEVICE_EXTENSION)DeviceObject->DeviceExtension;
  PIO_STACK_LOCATION IrpStack = IoGetCurrentIrpStackLocation(Irp);

  DbgPrint("[win32dd] Create driver.");
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

 DbgPrint("[win32dd] Close driver.");

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

  //
  // Create a pool with size = sizeof(PKPROCESSOR_STATE32)
  //
  KPROCESSOR_STATE32 ProcState;

  ULONG Level;
  ULONG Type;

  Irp->IoStatus.Status = STATUS_SUCCESS;
  Irp->IoStatus.Information = 0;

  IrpStack = IoGetCurrentIrpStackLocation(Irp);

  IoBuffer = Irp->AssociatedIrp.SystemBuffer;
  OutputLen = IrpStack->Parameters.DeviceIoControl.OutputBufferLength;
  InputLen = IrpStack->Parameters.DeviceIoControl.InputBufferLength;

  //
  // We hook basic functions.
  //
  IoControlCode = IrpStack->Parameters.DeviceIoControl.IoControlCode;

  switch ((IoControlCode & 0xFFFFFF0F)) {
    case IOCTL_GET_INFO: {
      struct Win32MemroyInfo *info = (void *)IoBuffer;
      int res = AddMemoryRanges(info, OutputLen);

      DbgPrint("[win32dd] Returning info on the system memory.\n");
      if(res > 0) {
        Irp->IoStatus.Information = res;
        NtStatus = STATUS_SUCCESS;
      } else {
        NtStatus = STATUS_INFO_LENGTH_MISMATCH;
      };

      Irp->IoStatus.Status = NtStatus;
    }; break;

    //
    // Generate the RAW Dump.
    //
    case IOCTL_WRITE_RAW_DUMP:
      DbgPrint("[win32dd] Lets generate a raw dump it !\n");

      //
      // We define the destination path.
      //

      RtlInitUnicodeString (&DestinationPath, IoBuffer);
      NtStatus = STATUS_SUCCESS;

      Level = (IoControlCode >> 6) & 0x3;
      Type = (IoControlCode >> 4) & 0x3;

      DbgPrint("Level: %d Type: %d\n", Level, Type);

      switch (Level) {
        case 0:
          NtStatus = IoWriteRawDump_Level0(DeviceObject, &DestinationPath);
          break;
        case 1:
          NtStatus = IoWriteRawDump_Level1(DeviceObject, &DestinationPath);
          break;
        default:
          NtStatus = IoWriteRawDump_Level0(DeviceObject, &DestinationPath);
          break;
      }

      if (NT_SUCCESS(NtStatus)) {
        IopFinalRawDumpStatus = STATUS_DONE;
      } else {
        IopFinalRawDumpStatus = STATUS_FAIL;
      }

      if (OutputLen == sizeof (ULONG)) {
        OutputBuffer = (PULONG)IoBuffer;
        OutputBuffer[0] = IopFinalRawDumpStatus;
        Irp->IoStatus.Information = sizeof(ULONG);
      }

      Irp->IoStatus.Status = NtStatus;
      break;

    case IOCTL_WRITE_CRSH_DUMP:
      DbgPrint("[win32dd] Lets generate a crash dump it !\n");

      //
      // We define the destination path.
      //
      RtlInitUnicodeString (&DestinationPath, IoBuffer);
      NtStatus = STATUS_SUCCESS;

      //
      // Indeed, this undocumented API is exported by ntoskrnl,
      // but to avoid hooking risks, I've decide to rewrite it
      // too.
      //
      KeSaveStateForHibernate(&ProcState);

      IopInitializeDCB();

      Level = (IoControlCode >> 6) & 0x3;
      Type = (IoControlCode >> 4) & 0x3;

      DbgPrint("--> Arguments (Level = %d, Type = %d)\n", Level, Type);

      if (Type == 1) {
        //
        // Just PFN 0 because this is a fixed page.
        //
        if (IopDumpControlBlock->MemoryDescriptor->Run[0].BasePage == 1) {
          IopDumpControlBlock->MemoryDescriptor->Run[0].BasePage = 0;
          IopDumpControlBlock->MemoryDescriptor->Run[0].PageCount += 1;
          IopDumpControlBlock->MemoryDescriptor->NumberOfPages += 1;
        }
      }

      NtStatus = IoWriteCrashDump(&DestinationPath,
                                  'TTAM',
                                  'TTAM',
                                  'NOOM',
                                  'SLOS',
                                  'TTAM',
                                  &ProcState.ContextFrame);

      IopFreeDCB(TRUE);

      if (NT_SUCCESS(NtStatus)) {
        IopFinalCrashDumpStatus = STATUS_DONE;
      } else {
        IopFinalCrashDumpStatus = STATUS_FAIL;
      }

      if (OutputLen == sizeof (ULONG)) {
        OutputBuffer = (PULONG)IoBuffer;
        OutputBuffer[0] = IopFinalCrashDumpStatus;
        Irp->IoStatus.Information = sizeof(ULONG);
      }

      Irp->IoStatus.Status = NtStatus;
      break;
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

  DbgPrint("  Win32dd - " WIN32DD_VERSION " - Physical memory acquisition\n");
  DbgPrint("  Copyright (c) 2012, Michael Cohen <scudette@gmail.com>\n");
  DbgPrint("  Copyright (c) 2007 - 2009, Matthieu Suiche <http://www.msuiche.net>\n");
  DbgPrint("  Copyright (c) 2008 - 2009, MoonSols <http://www.moonsols.com>\n");

  //
  // We define the unicode string for our device.
  //
  RtlInitUnicodeString (&DeviceName, L"\\Device\\" WIN32DD_DEVICE_NAME);

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
                                  &GUID_DEVCLASS_WIN32DD_DUMPER,
                                  &DeviceObject);

  if (!NT_SUCCESS(NtStatus)) {
    DbgPrint ("[win32dd] IoCreateDevice failed. => %08X\n", NtStatus);
    return NtStatus;
  }

  DriverObject->MajorFunction[IRP_MJ_CREATE] = wddCreate;
  DriverObject->MajorFunction[IRP_MJ_CLOSE] = wddClose;
  DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = wddDispatchDeviceControl;
  DriverObject->MajorFunction[IRP_MJ_READ] =  win32Read;
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
  RtlInitUnicodeString (&DeviceLink, L"\\DosDevices\\" WIN32DD_DEVICE_NAME);

  //
  // We create it's symbolic name.
  //
  NtStatus = IoCreateSymbolicLink (&DeviceLink,
                                   &DeviceName);

  //
  // If we reach this case, we cannot continue.
  //
  if (!NT_SUCCESS(NtStatus)) {
    DbgPrint ("[win32dd] IoCreateSymbolicLink failed. => %08X\n", NtStatus);
    IoDeleteDevice (DeviceObject);
  }

  return NtStatus;
}
