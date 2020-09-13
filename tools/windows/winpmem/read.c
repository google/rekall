/*
  Copyright 2018 Velocidex Innovations <mike@velocidex.com>
  Copyright 2014-2017 Google Inc.
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

#include "read.h"

// xxx: 
// This function's secret unspoken true name is "openPhysMemSectionHandle".
// It opens a section handle to the physicalMemory device and quicksaves the handle in the device extension for mapViewOfFile usage.
// It was named MemoryHandle, because we do not need to let everybody know more than that.
static int EnsureExtensionHandle(PDEVICE_EXTENSION extension) 
{
  NTSTATUS NtStatus;
  UNICODE_STRING PhysicalMemoryPath;
  OBJECT_ATTRIBUTES MemoryAttributes;

  /* Make sure we have a valid handle now. */
  if(!extension->MemoryHandle) 
  {
    RtlInitUnicodeString(&PhysicalMemoryPath, L"\\Device\\PhysicalMemory");

    InitializeObjectAttributes(&MemoryAttributes,
                               &PhysicalMemoryPath,
                               OBJ_KERNEL_HANDLE,
                               (HANDLE) NULL,
                               (PSECURITY_DESCRIPTOR) NULL);

    NtStatus = ZwOpenSection(&extension->MemoryHandle,
                             SECTION_MAP_READ, &MemoryAttributes);

    if (!NT_SUCCESS(NtStatus)) {
      WinDbgPrint("Failed ZwOpenSection(MemoryHandle) => %08X\n", NtStatus);
      return 0;
    }
  }

  return 1;
}


LONG PhysicalMemoryPartialRead(IN PDEVICE_EXTENSION extension,
                                      LARGE_INTEGER offset, PCHAR buf,
                                      ULONG count) 
{
  ULONG page_offset = offset.QuadPart % PAGE_SIZE;
  ULONG to_read = min(PAGE_SIZE - page_offset, count);
  PUCHAR mapped_buffer = NULL;
  SIZE_T ViewSize = PAGE_SIZE;
  NTSTATUS NtStatus;

  if (EnsureExtensionHandle(extension)) // xxx: Of course! Totally ensuring the device extension handle. ;-p
  {
    /* Map page into the Kernel AS */
    NtStatus = ZwMapViewOfSection(extension->MemoryHandle, (HANDLE) -1,
				  &mapped_buffer, 0L, PAGE_SIZE, &offset,
				  &ViewSize, ViewUnmap, 0, PAGE_READONLY);

    if (NT_SUCCESS(NtStatus)) {
      RtlCopyMemory(buf, mapped_buffer + page_offset, to_read);
      ZwUnmapViewOfSection((HANDLE)-1, mapped_buffer);

    } else {
      WinDbgPrint("Failed to Map page at 0x%llX\n", offset.QuadPart);
      RtlZeroMemory(buf, to_read);
    };
  };

  return to_read;
};


// Read a single page using MmMapIoSpace.
static LONG MapIOPagePartialRead(IN PDEVICE_EXTENSION extension,
                                 LARGE_INTEGER offset, PCHAR buf,
                                 ULONG count) 
{
  UNREFERENCED_PARAMETER(extension);
  ULONG page_offset = offset.QuadPart % PAGE_SIZE;
  ULONG to_read = min(PAGE_SIZE - page_offset, count);
  PUCHAR mapped_buffer = NULL;
  LARGE_INTEGER ViewBase;

  // Round to page size
  ViewBase.QuadPart = offset.QuadPart - page_offset;

  // Map exactly one page.
  mapped_buffer = MmMapIoSpace(ViewBase, PAGE_SIZE, MmCached);  
  // xxx: This will BSOD on HV with a KD attached or return Null if no KD is attached. It can't be helped.
  // xxx: I chose the MmCached because rumor has it that the cached property is more common on RAM-backed memory, and the non-cached property is more common for BARs.
  //      it's unsafe per definitionem, because this reverse way is not the intended usage.

	if (mapped_buffer) 
	{
		try 
		{
		  // Be extra careful here to not produce a BSOD.
		  RtlCopyMemory(buf, mapped_buffer+page_offset, to_read);
		} 
		except(EXCEPTION_EXECUTE_HANDLER) 
		{
		  WinDbgPrintDebug("Unable to read %d bytes from %p for %p\n", to_read, source, offset.QuadPart - page_offset);
		  MmUnmapIoSpace(mapped_buffer, PAGE_SIZE);
		  return -1;
		}

		MmUnmapIoSpace(mapped_buffer, PAGE_SIZE);
		return to_read;
		} 
	else 
	{
		// Failed to map page, return an error.
		return -1;
	}
}


// Read a single page using direct PTE mapping.
static LONG PTEMmapPartialRead(IN PDEVICE_EXTENSION extension,
			       LARGE_INTEGER offset, PCHAR buf,
			       ULONG count) 
{
  ULONG page_offset = offset.QuadPart % PAGE_SIZE;
  ULONG to_read = min(PAGE_SIZE - page_offset, count);
  LARGE_INTEGER ViewBase;
  LONG result = -1;

  // Round to page size
  ViewBase.QuadPart = offset.QuadPart - page_offset;

  // Map exactly one page.
  if(extension->pte_mmapper &&
     extension->pte_mmapper->remap_page(extension->pte_mmapper,
					offset.QuadPart - page_offset) ==
     PTE_SUCCESS) {
    char *source = (char *)(extension->pte_mmapper->rogue_page.value + page_offset);
    try {
      // Be extra careful here to not produce a BSOD. 
      // We would rather return an error than a BSOD.
      RtlCopyMemory(buf, source, to_read);
	  result = to_read;

    } except(EXCEPTION_EXECUTE_HANDLER) {
      WinDbgPrintDebug("Unable to read %d bytes from %p for %p\n", to_read, source, offset.QuadPart - page_offset);
	}
  }
  // Failed to map page, or an exception occured - error out.
  return result;
};


// xxx: yeah... maybe we should have some device state 
// that can be set to "DUMP_IN_PROGRESS". 
// It should be avoided in first place to do more than one DUMP acquisition at the same time simultaneously.
NTSTATUS DeviceRead(IN PDEVICE_EXTENSION extension, LARGE_INTEGER offset,
                           PCHAR buf, ULONG count, OUT ULONG *total_read,
                           LONG (*handler)(IN PDEVICE_EXTENSION, LARGE_INTEGER,
                                           PCHAR, ULONG)) {
  int result = 0;

  *total_read = 0;

  ExAcquireFastMutex(&extension->mu);
  while(*total_read < count) {
    result = handler(extension, offset, buf, count - *total_read); // xxx: that is weird

    /* Error Occured. */
    if(result < 0)
      goto error;

    /* No data available. */
    if(result==0) {
      break;
    };

    offset.QuadPart += result;
    buf += result;
    *total_read += result;
  };

  ExReleaseFastMutex(&extension->mu);
  return STATUS_SUCCESS;

error:
  ExReleaseFastMutex(&extension->mu);
  return STATUS_IO_DEVICE_ERROR;
};



NTSTATUS PmemRead(IN PDEVICE_OBJECT  DeviceObject, IN PIRP  Irp) 
{
	PVOID Buf;       //Buffer provided by user space.
	ULONG BufLen;    //Buffer length for user provided buffer.
	LARGE_INTEGER BufOffset; // The file offset requested from userspace.
	PIO_STACK_LOCATION pIoStackIrp;
	PDEVICE_EXTENSION extension;
	NTSTATUS status = STATUS_SUCCESS;
	ULONG total_read = 0;

	PAGED_CODE();

	// xxx: no way this could possibly run on irql in this driver. 
	// On second thought, there might be a malicious driver trying to kill winpmem 
	// with a created IRP of IRQL > 0 (paranoid, I know). In this case ...
	
	if(KeGetCurrentIrql() != PASSIVE_LEVEL) 
	{
		status = STATUS_SUCCESS;
		goto exit;
	}

	extension = DeviceObject->DeviceExtension;

	pIoStackIrp = IoGetCurrentIrpStackLocation(Irp);
	BufLen = pIoStackIrp->Parameters.Read.Length;
	BufOffset = pIoStackIrp->Parameters.Read.ByteOffset;
	Buf =  Irp->UserBuffer; 
	// xxx: what we get from userspace is inside here for the NEITHER I/O type. 
	
	// xxx:
	// maybe it's even a kernel driver or rootkit calling us for help.
	// As long as it's coming on irql 0, we will gladly help out.
	// I will be referring to it mostly as the "usermode program", but also keep in mind it could be a kernelmode system thread.
	
	// Do security checkings now. 
	// The usermode program is not allowed to order more than ONE PAGE_SIZE at a time.
	// But the arbitrary read/write allows up to 1-PAGESIZE bytes. So...
	
	if (!(Buf))
	{
		DbgPrint("error: provided buffer in read request was invalid.\n");
		status = STATUS_INVALID_PARAMETER;
		goto exit;
	}
	
	if (BufLen > PAGE_SIZE)
	{
		DbgPrint("Complain: the caller wants to read more than a PAGE_SIZE!\n");
		// xxx: We cannot clamp it to PAGE_SIZE, that might lead to corrupt data for the usermode program.
		// Better directly reject this request then. 
		// What would be good? "Not implemented"?
		status = STATUS_NOT_IMPLEMENTED;
		goto exit;
	}
	
	// xxx: Those usermode programs should disturb us only with serious requests. We are a busy driver.
	
	if (!(BufLen))
	{
		DbgPrint("Complain: the caller  wants to read less than one byte.\n");
		// xxx: What would be good? "Not implemented"?
		status = STATUS_NOT_IMPLEMENTED;
		goto exit;
	}
	
	// xxx: might look into ntstatus.h for a nicer NTSTATUS code.
	
	// Now check if the usermode program spoke the truth.
	try 
    {
		ProbeForWrite( Buf, BufLen, 1 ); // xxx: If we would drop the arbitrary read/write primitive from usermode, 
		// we could put something else then 1 here.
	}
	except(EXCEPTION_EXECUTE_HANDLER)
	{

		status = GetExceptionCode();
		DbgPrint("Error: 0x%08x, probe in PmemRead. A naughty process sent us a bad/nonexisting buffer.\n", status);
		// Of course now we don't continue. 
		
		status = STATUS_SUCCESS; // to the I/O manager: everything's under control. Nothing to see.
		goto exit;
	}
	
	#ifdef MDL_SECURE_THE_NEITHER_IO_FURTHER
        
		// xxx:
        // Yeah. No. You could order an MDL and lock the (usermode buffer's) pages. 
		// You will lose the performance advantage from NEITHER I/O.
        // Just for the sake of completeness: this is what the I/O manager would now do on the freshly received _out usermode buffer when DIRECT I/O is wanted.
		// We would lose the NEITHER I/O performance boost, because it would merely end in a custom DIRECT I/O mode implementation.
		
	#endif
	
	// All things considered, the buffer looked good, of right size, and was accessible for write.
	// We will use it now.

	//DbgPrint("PmemRead\n");
	//DbgPrint(" - BufLen: 0x%x\r\n", BufLen);
	//DbgPrint(" - BufOffset: 0x%llx\r\n", BufOffset.QuadPart);

	if ((extension->mode) == ACQUISITION_MODE_PHYSICAL_MEMORY)
	{
		status = DeviceRead(extension, BufOffset, Buf, BufLen, &total_read, PhysicalMemoryPartialRead);
	}
	else if ((extension->mode) == ACQUISITION_MODE_MAP_IO_SPACE)
	{
		status = DeviceRead(extension, BufOffset, Buf, BufLen, &total_read, MapIOPagePartialRead);
	}
	else if ((extension->mode) == ACQUISITION_MODE_PTE_MMAP)
	{
		status = DeviceRead(extension, BufOffset, Buf, BufLen, &total_read, PTEMmapPartialRead);
	}
	else
	{
		DbgPrint("This acquisition mode is not supported!\n");
		status = STATUS_NOT_IMPLEMENTED;
		BufLen = 0;
	}

	exit:
	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = total_read;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return status;
}

#if PMEM_WRITE_ENABLED == 1

NTSTATUS PmemWrite(IN PDEVICE_OBJECT  DeviceObject, IN PIRP  Irp) 
{
	PVOID Buf;       //Buffer provided by user space.
	ULONG BufLen;    //Buffer length for user provided buffer.
	LARGE_INTEGER BufOffset; // The file offset requested from userspace.
	PIO_STACK_LOCATION pIoStackIrp;
	PDEVICE_EXTENSION extension;
	NTSTATUS status = STATUS_SUCCESS;
	SIZE_T ViewSize = PAGE_SIZE;
	PUCHAR mapped_buffer = NULL;
	ULONG page_offset = 0;
	LARGE_INTEGER offset;

	PAGED_CODE();

	// xxx: no way this could possibly run on irql in this driver. 
	// On second thought, there might be a malicious driver trying to kill winpmem 
	// with a created IRP of IRQL > 0 (paranoid, I know). In this case ...

	if (KeGetCurrentIrql() != PASSIVE_LEVEL) 
	{
		status = STATUS_SUCCESS;
		goto exit;
	}

	extension = DeviceObject->DeviceExtension;

	if (!extension->WriteEnabled) 
	{
		status = STATUS_ACCESS_DENIED;
		WinDbgPrint("Write mode not enabled.\n");
		goto exit;
	}

	pIoStackIrp = IoGetCurrentIrpStackLocation(Irp);
	
	// buffer length is going to be checked for being between 1-PAGESIZE.
	BufLen = pIoStackIrp->Parameters.Write.Length;

	// Where to write exactly.
	BufOffset = pIoStackIrp->Parameters.Write.ByteOffset;
	
	Buf = pIoStackIrp->Parameters.DeviceIoControl.Type3InputBuffer;
	// Buf = (PCHAR)(Irp->AssociatedIrp.SystemBuffer);
	
	// xxx: hope the caller knows what he's doing here. That's an arbitrary read to anywhere from usermode.
	// Maybe we should insert some kind of quick puzzle to ensure the caller is sane.
	
	// Security checks now.
	
	if (!(Buf))
	{
		DbgPrint("error: provided buffer in write request was invalid.\n");
		status = STATUS_INVALID_PARAMETER;
		goto exit;
	}
	
	if (BufLen > PAGE_SIZE)
	{
		DbgPrint("Complain: the caller wants to write more than a PAGE_SIZE!\n");
		// xxx: We cannot clamp it to PAGE_SIZE, that might lead to corrupt data for the usermode program.
		// Better directly reject this request then. 
		// What would be good? "Not implemented"?
		status = STATUS_NOT_IMPLEMENTED;
		goto exit;
	}
	
	// xxx: Those usermode programs should disturb us only with serious requests. We are a busy driver.
	
	if (!(BufLen))
	{
		DbgPrint("Complain: the caller  wants to write less than one byte.\n");
		// xxx: What would be good? "Not implemented"?
		status = STATUS_NOT_IMPLEMENTED;
		goto exit;
	}
	
	// xxx: might look into ntstatus.h for a nicer NTSTATUS code.
	
	// Now check if the usermode program spoke the truth.
	try 
    {
		// xxx: jep. that's a read from our point of view, though we are implementing a WriteFile.
		ProbeForRead( Buf, BufLen, 1 ); // xxx: If we would drop the arbitrary read/write primitive from usermode, 
		// we could put something else then 1 here.
	}
	except(EXCEPTION_EXECUTE_HANDLER)
	{

		status = GetExceptionCode();
		DbgPrint("Error: 0x%08x, probe in PmemWrite. A naughty process sent us a bad/nonexisting buffer.\n", status);
		// Of course now we don't continue. 
		
		status = STATUS_SUCCESS; // to the I/O manager: everything's under control. Nothing to see.
		goto exit;
	}
	
	#ifdef MDL_SECURE_THE_NEITHER_IO_FURTHER
        
		// xxx:
        // Yeah. No. You could order an MDL and lock the (usermode buffer's) pages now. 
		// But we are only reading 'some caller data'. 
		// If the caller does not know what he is doing, there are going to be worse problems.
		
	#endif
	
	// xxx: All things considered, the buffer looked good, of right size, and was accessible for reading.
	
	// We will use it to write #somewhere# #something# given by #somebody#. Incredible. I like the 'solve puzzle first' idea.

	page_offset = BufOffset.QuadPart % PAGE_SIZE;
	offset.QuadPart = BufOffset.QuadPart - page_offset;  // Page aligned.

	// How much we need to write rounded up to the next page.
	ViewSize = BufLen + page_offset;
	ViewSize += PAGE_SIZE - (ViewSize % PAGE_SIZE);

	/* Map memory into the Kernel AS */
	if (EnsureExtensionHandle(extension)) // xxx: totally ensuring the device extension handle. *nods*
	{   								  // xxx: I like that we use this method for the arbitrary write, it's the most safest (and slowest).
		status = ZwMapViewOfSection(extension->MemoryHandle, (HANDLE) -1,
				&mapped_buffer, 0L, PAGE_SIZE, &offset,
				&ViewSize, ViewUnmap, 0, PAGE_READWRITE);

		if (NT_SUCCESS(status)) 
		{
		  RtlCopyMemory(mapped_buffer + page_offset, Buf, BufLen);
		  ZwUnmapViewOfSection((HANDLE)-1, mapped_buffer);
		}
		else 
		{
		  WinDbgPrint("Failed to map view %lld %ld (%ld).\n", offset, ViewSize, status);
		}
	}

	exit:
	Irp->IoStatus.Status = status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return status;
}

#endif
