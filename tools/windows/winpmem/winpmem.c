/*
  Copyright 2018 Velocidex Innovations <mike@velocidex.com>
  Copyright 2014-2017 Google Inc.

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
#include "read.h"
#include "kd.h"

// xxx: slightly enhanced non-null pointer checking / better kernel VA sanity checking.
#if defined(_WIN64)
SIZE_T ValidKernel = 0xffff000000000000;
#else
SIZE_T ValidKernel = 0x80000000;
#endif


// The following globals are populated in the kernel context from DriverEntry
// and reported to the user context.

// The kernel CR3
LARGE_INTEGER CR3;
// xxx: We should maybe move all scattered globals into one header file for structs & data, to have a better overview what globals are defined. 


DRIVER_UNLOAD IoUnload;

VOID IoUnload(IN PDRIVER_OBJECT DriverObject) 
{
	UNICODE_STRING DeviceLinkUnicodeString;
	PDEVICE_OBJECT pDeviceObject = NULL;
	 PDEVICE_EXTENSION ext = NULL;

	ASSERT(DriverObject); // xxx: No checks needed unless the kernel is in serious trouble.

	pDeviceObject = DriverObject->DeviceObject;

	// xxx: The device object should be fine unless the device creation failed in DriverEntry.
	// That could happen for example on name collision (someone else has a device called like that.)
	// The following check therefore may actually fail and needs a real check.

	if ((SIZE_T) pDeviceObject > ValidKernel)
	{
		ASSERT((SIZE_T) pDeviceObject->DeviceExtension > ValidKernel); // does not happen. 
		ext=(PDEVICE_EXTENSION) pDeviceObject->DeviceExtension;

		RtlInitUnicodeString (&DeviceLinkUnicodeString, L"\\??\\" PMEM_DEVICE_NAME);
		IoDeleteSymbolicLink (&DeviceLinkUnicodeString);

		if ((SIZE_T) (ext->pte_mmapper) > ValidKernel)
		{
		  pte_mmap_windows_delete(ext->pte_mmapper);
		}

		IoDeleteDevice(pDeviceObject);
	}
}


/*
  Gets information about the memory layout.

  - The Physical memory address ranges.
*/
NTSTATUS AddMemoryRanges(struct PmemMemoryInfo *info, int len) 
{
  PPHYSICAL_MEMORY_RANGE MmPhysicalMemoryRange = MmGetPhysicalMemoryRanges();
  int number_of_runs = 0;
  int required_length;

  // Enumerate address ranges.
  // This routine returns the virtual address of a nonpaged pool block which contains the physical memory ranges in the system.
  // The returned block contains physical address and page count pairs.
  // The last entry contains zero for both.
  // The caller must understand that this block can change at any point before or after this snapshot.
  // It is the caller's responsibility to free this block.

  if (MmPhysicalMemoryRange == NULL) 
  {
    return STATUS_ACCESS_DENIED;
  };

  /** Find out how many ranges there are. */
  for(number_of_runs=0;
      (MmPhysicalMemoryRange[number_of_runs].BaseAddress.QuadPart) ||
        (MmPhysicalMemoryRange[number_of_runs].NumberOfBytes.QuadPart);
      number_of_runs++);
	  
	WinDbgPrint("Memory range runs found: %d.\n",number_of_runs);

  required_length = (sizeof(struct PmemMemoryInfo) +
                     number_of_runs * sizeof(PHYSICAL_MEMORY_RANGE));

  /* Do we have enough space? */
  if(len < required_length) return STATUS_INFO_LENGTH_MISMATCH;

  RtlZeroMemory(info, required_length);

  info->NumberOfRuns.QuadPart = number_of_runs;
  RtlCopyMemory(&info->Run[0], MmPhysicalMemoryRange, number_of_runs * sizeof(PHYSICAL_MEMORY_RANGE));

  ExFreePool(MmPhysicalMemoryRange);

  return STATUS_SUCCESS;
};

__drv_dispatchType(IRP_MJ_CREATE) DRIVER_DISPATCH wddCreate;

NTSTATUS wddCreate(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) 
{
//  PDEVICE_EXTENSION ext=(PDEVICE_EXTENSION)DeviceObject->DeviceExtension;
  //PIO_STACK_LOCATION IrpStack = IoGetCurrentIrpStackLocation(Irp);
  if (!DeviceObject || !Irp) 
  {
	return STATUS_INVALID_PARAMETER;
  }
  Irp->IoStatus.Status = STATUS_SUCCESS;
  Irp->IoStatus.Information = 0;

  IoCompleteRequest(Irp,IO_NO_INCREMENT);
  return STATUS_SUCCESS;
};


__drv_dispatchType(IRP_MJ_CLOSE) DRIVER_DISPATCH wddClose;

NTSTATUS wddClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp) 
{
  PDEVICE_EXTENSION ext=(PDEVICE_EXTENSION)DeviceObject->DeviceExtension;
//  PIO_STACK_LOCATION IrpStack = IoGetCurrentIrpStackLocation(Irp);
  if (!DeviceObject || !Irp) 
  {
		return STATUS_INVALID_PARAMETER;
  }
  if(ext->MemoryHandle != 0) 
  {
    ZwClose(ext->MemoryHandle);
    ext->MemoryHandle = 0;
  };

  Irp->IoStatus.Status = STATUS_SUCCESS;
  Irp->IoStatus.Information = 0;

  IoCompleteRequest(Irp,IO_NO_INCREMENT);

  return STATUS_SUCCESS;
}



__drv_dispatchType(IRP_MJ_DEVICE_CONTROL) DRIVER_DISPATCH wddDispatchDeviceControl;

NTSTATUS wddDispatchDeviceControl(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
  PIO_STACK_LOCATION IrpStack;
  NTSTATUS status = STATUS_INVALID_PARAMETER;
  ULONG IoControlCode;
  PVOID inBuffer;
  PVOID outBuffer;
  PDEVICE_EXTENSION ext;
  ULONG InputLen, OutputLen;
  struct PmemMemoryInfo * info; // PTR
  LARGE_INTEGER kernelbase;
  
  PAGED_CODE();
  
  if(KeGetCurrentIrql() != PASSIVE_LEVEL) 
  {
    status = STATUS_SUCCESS;
    goto exit;
  }

  ext = (PDEVICE_EXTENSION)DeviceObject->DeviceExtension;

  Irp->IoStatus.Information = 0;

  IrpStack = IoGetCurrentIrpStackLocation(Irp);

  inBuffer = IrpStack->Parameters.DeviceIoControl.Type3InputBuffer;
  outBuffer = Irp->UserBuffer;
  // IoBuffer = Irp->AssociatedIrp.SystemBuffer;
  
  
  OutputLen = IrpStack->Parameters.DeviceIoControl.OutputBufferLength;
  InputLen = IrpStack->Parameters.DeviceIoControl.InputBufferLength;
  IoControlCode = IrpStack->Parameters.DeviceIoControl.IoControlCode;

  switch ((IoControlCode & 0xFFFFFF0F))
  {

    // Return information about memory layout etc through this ioctrl.
  case IOCTL_GET_INFO: 
  {
	
	if (!(outBuffer))
	{
		DbgPrint("Error: outuffer invalid in device io dispatch.\n");
		status = STATUS_INVALID_PARAMETER;
		goto exit;
	}

    if (OutputLen < sizeof(struct PmemMemoryInfo)) 
	{
		DbgPrint("Error: outbuffer too small for even the smallest info struct!\n");
        status = STATUS_INFO_LENGTH_MISMATCH;
        goto exit;
    }
	
	try 
	{
		ProbeForRead( outBuffer, sizeof(struct PmemMemoryInfo), sizeof( UCHAR ) ); 
		ProbeForWrite( outBuffer, sizeof(struct PmemMemoryInfo), sizeof( UCHAR ) ); 
	}
	except(EXCEPTION_EXECUTE_HANDLER)
	{
		status = GetExceptionCode();
		DbgPrint("Error: 0x%08x, probe in Device io dispatch, outbuffer. A naughty process sent us a bad/nonexisting buffer.\n", status); 
		
		status = STATUS_SUCCESS; // to the I/O manager: everything's under control. Nothing to see here.
		goto exit;
	}
	
	info = (void *) outBuffer;

    // Ensure we clear the buffer first.
    RtlZeroMemory(info, sizeof(struct PmemMemoryInfo));

	status = AddMemoryRanges(info, OutputLen);

    if (status != STATUS_SUCCESS) 
	{
		DbgPrint("Error: AddMemoryRanges returned %08x. output buffer size: 0x%x\n",status,OutputLen);
		goto exit;
    }

    WinDbgPrint("Returning info on the system memory.\n");

    // We are currently running in user context which means __readcr3() will
    // return the process CR3. So we return the kernel CR3 we found
    // when loading.
    info->CR3.QuadPart = CR3.QuadPart; // The saved CR3 from DriverEntry/System process context.
    info->NtBuildNumber.QuadPart = (SIZE_T) *NtBuildNumber;
    info->NtBuildNumberAddr.QuadPart = (SIZE_T) NtBuildNumber;
    kernelbase.QuadPart = KernelGetModuleBaseByPtr(); // I like to have that saved first in normal kernelspace und not directly into usermode buffer.
	// xxx: I'd like a KDBG here, too.
	
	ASSERT((SIZE_T) kernelbase.QuadPart > ValidKernel);
	WinDbgPrint("Kernelbase: %016llx.\n",kernelbase.QuadPart);
	info->KernBase.QuadPart = KernelGetModuleBaseByPtr();

    // Fill in KPCR.
    GetKPCR(info);

    // This is the length of the response.
    Irp->IoStatus.Information = sizeof(struct PmemMemoryInfo) + info->NumberOfRuns.LowPart * sizeof(PHYSICAL_MEMORY_RANGE);

    status = STATUS_SUCCESS;
  }; break;

  // set or change mode and check availability of neccessary functions
  case IOCTL_SET_MODE: 
  {
    WinDbgPrint("Setting Acquisition mode.\n");
	
	if ((!(inBuffer)) || (InputLen < sizeof(u32))) // are you really sure an enum is a u32?
	{
		DbgPrint("InBuffer in device io dispatch was invalid.\n");
		status = STATUS_INFO_LENGTH_MISMATCH;
		goto exit;
	}
	
	try 
	{
		ProbeForRead( inBuffer, sizeof(u32), sizeof( UCHAR ) ); 
	}
	except(EXCEPTION_EXECUTE_HANDLER)
	{
		status = GetExceptionCode();
		DbgPrint("Error: 0x%08x, probe in Device io dispatch, Inbuffer. A naughty process sent us a bad/nonexisting buffer.\n", status); 
		
		status = STATUS_SUCCESS; // to the I/O manager: everything's under control. Nothing to see here.
		goto exit;
	}
	
	// security checks finished

      enum PMEM_ACQUISITION_MODE mode = *(u32 *) inBuffer; 

      switch(mode) 
	  {
      case ACQUISITION_MODE_PHYSICAL_MEMORY:
        WinDbgPrint("Using physical memory device for acquisition.\n");
        status = STATUS_SUCCESS;
		ext->mode = mode;
        break;

      case ACQUISITION_MODE_MAP_IO_SPACE:
        WinDbgPrint("Using MmMapIoSpace for acquisition.\n");
        status = STATUS_SUCCESS;
		ext->mode = mode;
        break;

      case ACQUISITION_MODE_PTE_MMAP:
        if (!(ext->pte_mmapper)) 
		{
			WinDbgPrint("Kernel APIs required for this method are not available.\n");
			status = STATUS_UNSUCCESSFUL;
        } 
		else 
		{
			WinDbgPrint("Using PTE Remapping for acquisition.\n");
			status = STATUS_SUCCESS;
			ext->mode = mode;
        };
        break;

      default:
        WinDbgPrint("Invalid acquisition mode %d.\n", mode);
        status = STATUS_INVALID_PARAMETER;
      };

	
  }; break;


#if PMEM_WRITE_ENABLED == 1
  case IOCTL_WRITE_ENABLE: 
  {
	
	// xxx: thanfully for me, we do not access any in/out buffers here.
    ext->WriteEnabled = !ext->WriteEnabled;
    WinDbgPrint("Write mode is %d. Do you know what you are doing?\n", ext->WriteEnabled);
    status = STATUS_SUCCESS;
	
  }; break;

#endif

  default: 
  {
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
  
  UNREFERENCED_PARAMETER(RegistryPath);

  WinDbgPrint("WinPMEM - " PMEM_VERSION " \n");

#if PMEM_WRITE_ENABLED == 1
  WinDbgPrint("WinPMEM write support available!\n");
#endif

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

  if (!NT_SUCCESS(NtStatus)) 
  {
    WinDbgPrint ("IoCreateDevice failed. => %08X\n", NtStatus);
    return NtStatus;
  }

  DriverObject->MajorFunction[IRP_MJ_CREATE] = wddCreate;
  DriverObject->MajorFunction[IRP_MJ_CLOSE] = wddClose;
  DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = wddDispatchDeviceControl;
  DriverObject->MajorFunction[IRP_MJ_READ] = PmemRead; // xxx: this is a function that copies tons of data, in the range of Gigabytes.
                                                       //      therefore using NEITHER I/O.

#if PMEM_WRITE_ENABLED == 1
  {
    // Make sure that the drivers with write support are clearly marked as such.
    static char TAG[] = "Write Supported";
  }

  // Support writing.
  DriverObject->MajorFunction[IRP_MJ_WRITE] = PmemWrite;
  
#endif

	DriverObject->DriverUnload = IoUnload;
	
	// We need to set NEITHER, because otherwise for read/write requests the I/O manager cannot know where we except the usermode buffer.
	DeviceObject->Flags &= ~DO_DIRECT_IO;
	DeviceObject->Flags &= ~DO_BUFFERED_IO;
	
  // SetFlag(DeviceObject->Flags, DO_BUFFERED_IO ); // xxx: we will still do BUFFERED I/O for GET_INFO, SET_MODE, and WRITE_ENABLE, 
													// as they do not represent large amounts of data.
  
	DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING; // xxx: I/O manager will do that anyway because it's in the driver entry.

  /*
  xxx:
  it's either BUFFERED OR DIRECT I/O.
  We could really use DIRECT I/O. Or NEITHER. 
  Writing the dump is REALLY SLOW currently. Worryingly so when it comes to 8 or 16 GB. 
   A rootkit is not nice and it will not wait and do a pending on its evil actions until the dump has been fully written. 
   A fast readwrite-dumpfile method could really help! 
  */

  RtlInitUnicodeString (&DeviceLink, L"\\??\\" PMEM_DEVICE_NAME);

  NtStatus = IoCreateSymbolicLink (&DeviceLink, &DeviceName);
  
  if (!NT_SUCCESS(NtStatus)) 
  {
	  // xxx: Don't do that:!! It didn't work out so it's not freeable.
	  // IoDeleteSymbolicLink(&DeviceLink);
	  
	  WinDbgPrint("IoCreateSymbolicLink failed. => %08X\n", NtStatus);
	  // IoDeleteDevice(DeviceObject); // xxx: Don't do that!! The unload routine will take care of that already.
	  goto error;
  }

  // Populate globals in kernel context.
  // Used when virtual addressing is enabled, hence when the PG bit is set in CR0. 
  // CR3 enables the processor to translate linear addresses into physical addresses by locating the page directory and page tables for the current task. 
  // Typically, the upper 20 bits of CR3 become the page directory base register (PDBR), which stores the physical address of the first page directory entry. 
  // If the PCIDE bit in CR4 is set, the lowest 12 bits are used for the process-context identifier (PCID)
  CR3.QuadPart = __readcr3();

  // Initialize the device extension with safe defaults.
  extension = DeviceObject->DeviceExtension;
  extension->mode = ACQUISITION_MODE_PHYSICAL_MEMORY;
  extension->MemoryHandle = 0;

#if _WIN64
  // Disable pte mapping for 32 bit systems.
  extension->pte_mmapper = pte_mmap_windows_new();
  
  if (extension->pte_mmapper == NULL) 
  {
	  // IoDeleteDevice(DeviceObject); // WTF?
	  goto error;
  }
  extension->pte_mmapper->loglevel = PTE_ERR;
  
  // extension->mode = ACQUISITION_MODE_PTE_MMAP;
#else
  extension->pte_mmapper = NULL;
#endif

  ExInitializeFastMutex(&extension->mu);

  WinDbgPrint("Driver intialization completed.\n");
  return NtStatus;

 error:
  return STATUS_UNSUCCESSFUL;
}
