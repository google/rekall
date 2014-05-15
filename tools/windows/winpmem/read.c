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

#include "read.h"

static int EnsureExtensionHandle(PDEVICE_EXTENSION extension) {
  NTSTATUS NtStatus;
  UNICODE_STRING PhysicalMemoryPath;
  OBJECT_ATTRIBUTES MemoryAttributes;

  /* Make sure we have a valid handle now. */
  if(!extension->MemoryHandle) {
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
  };

  return 1;
}


static LONG PhysicalMemoryPartialRead(IN PDEVICE_EXTENSION extension,
                                      LARGE_INTEGER offset, PCHAR buf,
                                      ULONG count) {
  ULONG page_offset = offset.QuadPart % PAGE_SIZE;
  ULONG to_read = min(PAGE_SIZE - page_offset, count);
  PUCHAR mapped_buffer = NULL;
  SIZE_T ViewSize = PAGE_SIZE;
  NTSTATUS NtStatus;


  if (EnsureExtensionHandle(extension)) {
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
                                 ULONG count) {
  ULONG page_offset = offset.QuadPart % PAGE_SIZE;
  ULONG to_read = min(PAGE_SIZE - page_offset, count);
  PUCHAR mapped_buffer = NULL;
  SIZE_T ViewSize = PAGE_SIZE;
  NTSTATUS NtStatus;
  LARGE_INTEGER ViewBase;

  // Round to page size
  ViewBase.QuadPart = offset.QuadPart - page_offset;

  // Map exactly one page.
  mapped_buffer = Pmem_KernelExports.MmMapIoSpace(
    ViewBase, PAGE_SIZE, MmNonCached);

  if (mapped_buffer) {
    RtlCopyMemory(buf, mapped_buffer + page_offset, to_read);
  } else {
    // Failed to map page, null fill the buffer.
    RtlZeroMemory(buf, to_read);
  };

  Pmem_KernelExports.MmUnmapIoSpace(mapped_buffer, PAGE_SIZE);

  return to_read;
};


// Read a single page using direct PTE mapping.
static LONG PTEMmapPartialRead(IN PDEVICE_EXTENSION extension,
			       LARGE_INTEGER offset, PCHAR buf,
			       ULONG count) {
  ULONG page_offset = offset.QuadPart % PAGE_SIZE;
  ULONG to_read = min(PAGE_SIZE - page_offset, count);
  PUCHAR mapped_buffer = NULL;
  SIZE_T ViewSize = PAGE_SIZE;
  NTSTATUS NtStatus;
  LARGE_INTEGER ViewBase;

  // Round to page size
  ViewBase.QuadPart = offset.QuadPart - page_offset;

  // Map exactly one page.
  if(extension->pte_mmapper->remap_page(extension->pte_mmapper,
					offset.QuadPart - page_offset) ==
     PTE_SUCCESS) {
    RtlCopyMemory(buf, (char *)(extension->pte_mmapper->rogue_page.value +
				page_offset), to_read);
  } else {
    // Failed to map page, null fill the buffer.
    RtlZeroMemory(buf, to_read);
  };

  return to_read;
};


static NTSTATUS DeviceRead(IN PDEVICE_EXTENSION extension, LARGE_INTEGER offset,
                           PCHAR buf, ULONG count, OUT ULONG *total_read,
                           LONG (*handler)(IN PDEVICE_EXTENSION, LARGE_INTEGER,
                                           PCHAR, ULONG)) {
  int result = 0;

  *total_read = 0;

  // Ensure we only run on a single CPU.
  KeSetSystemAffinityThread((__int64)1);

  while(*total_read < count) {
    result = handler(extension, offset, buf, count - *total_read);

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

  KeRevertToUserAffinityThread();
  return STATUS_SUCCESS;

 error:
  KeRevertToUserAffinityThread();
  return STATUS_IO_DEVICE_ERROR;
};


NTSTATUS PmemRead(IN PDEVICE_OBJECT  DeviceObject, IN PIRP  Irp) {
  PVOID Buf;       //Buffer provided by user space.
  ULONG BufLen;    //Buffer length for user provided buffer.
  LARGE_INTEGER BufOffset; // The file offset requested from userspace.
  ULONG DataLen;  //Buffer length for Driver Data Buffer
  PIO_STACK_LOCATION pIoStackIrp;
  PDEVICE_EXTENSION extension;
  NTSTATUS status = STATUS_SUCCESS;
  ULONG total_read = 0;

  // We must be running in PASSIVE_LEVEL or we bluescreen here. We
  // theoretically should always be running at PASSIVE_LEVEL here, but
  // in case we ended up here at the wrong IRQL its better to bail
  // than to bluescreen.
  if(KeGetCurrentIrql() != PASSIVE_LEVEL) {
    status = STATUS_ABANDONED;
    goto exit;
  };

  extension = DeviceObject->DeviceExtension;

  pIoStackIrp = IoGetCurrentIrpStackLocation(Irp);
  BufLen = pIoStackIrp->Parameters.Read.Length;
  BufOffset = pIoStackIrp->Parameters.Read.ByteOffset;
  Buf = (PCHAR)(Irp->AssociatedIrp.SystemBuffer);

  switch(extension->mode) {

    // Read using the physical memory handle.
  case ACQUISITION_MODE_PHYSICAL_MEMORY:
    status = DeviceRead(extension, BufOffset, Buf, BufLen, &total_read,
                        PhysicalMemoryPartialRead);
    break;

  case ACQUISITION_MODE_MAP_IO_SPACE:
    status = DeviceRead(extension, BufOffset, Buf, BufLen, &total_read,
                        MapIOPagePartialRead);
    break;

  case ACQUISITION_MODE_PTE_MMAP_WITH_PCI_PROBE:
  case ACQUISITION_MODE_PTE_MMAP:
    status = DeviceRead(extension, BufOffset, Buf, BufLen, &total_read,
                        PTEMmapPartialRead);
    break;

  default:
    WinDbgPrint("Acquisition mode %u not supported.\n", extension->mode);
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

NTSTATUS PmemWrite(IN PDEVICE_OBJECT  DeviceObject, IN PIRP  Irp) {
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

  // We must be running in PASSIVE_LEVEL or we bluescreen here. We
  // theoretically should always be running at PASSIVE_LEVEL here, but
  // in case we ended up here at the wrong IRQL its better to bail
  // than to bluescreen.
  if(KeGetCurrentIrql() != PASSIVE_LEVEL) {
    status = STATUS_ABANDONED;
    goto exit;
  };

  extension = DeviceObject->DeviceExtension;

  if (!extension->WriteEnabled) {
    status = STATUS_ACCESS_DENIED;
    WinDbgPrint("Write mode not enabled.\n");
    goto exit;
  };

  pIoStackIrp = IoGetCurrentIrpStackLocation(Irp);
  BufLen = pIoStackIrp->Parameters.Write.Length;

  // Where to write exactly.
  BufOffset = pIoStackIrp->Parameters.Write.ByteOffset;
  Buf = (PCHAR)(Irp->AssociatedIrp.SystemBuffer);

  page_offset = BufOffset.QuadPart % PAGE_SIZE;
  offset.QuadPart = BufOffset.QuadPart - page_offset;  // Page aligned.

  // How much we need to write rounded up to the next page.
  ViewSize = BufLen + page_offset;
  ViewSize += PAGE_SIZE - (ViewSize % PAGE_SIZE);

  /* Map memory into the Kernel AS */
  if (EnsureExtensionHandle(extension)) {
    status = ZwMapViewOfSection(extension->MemoryHandle, (HANDLE) -1,
				&mapped_buffer, 0L, PAGE_SIZE, &offset,
				&ViewSize, ViewUnmap, 0, PAGE_READWRITE);

    if (NT_SUCCESS(status)) {
      RtlCopyMemory(mapped_buffer + page_offset, Buf, BufLen);
      ZwUnmapViewOfSection((HANDLE)-1, mapped_buffer);
    } else {
      WinDbgPrint("Failed to map view %lld %ld (%ld).\n", offset, ViewSize,
		  status);
    }
  }

 exit:
  Irp->IoStatus.Status = status;
  IoCompleteRequest(Irp, IO_NO_INCREMENT);

  return status;
}

#endif
